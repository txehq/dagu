"""Page before a worker machine's credentials expire (TXE-7226, shipped with the worker kit by TXE-7233).

The worker kit runs this on every machine it installs: hourly, through the launchd agent
com.txe.dagu-credential-watch (install.sh) or the systemd user timer
txe-dagu-credential-watch.timer (install-systemd.sh). It is the only copy of the machine-side
check; the cluster-side heartbeat watch stays in txehq/txe (ops/dagu/machine-watch.py serve).

  credential-watch.py --home HOME --webhook-file FILE --state STATE [--credential-file PATH]...
                      [--warn-days 7] [--label L]
  credential-watch.py --home HOME --dry-run
  credential-watch.py --check-webhook FILE

It finds the expiry of every credential the worker and tunnel use under HOME (the TXE home): the
tunnel kubeconfig's tokens and inline client certificates, and every *-credential.json refresh
token, and each --credential-file (the worker's credential when the install was given one that
the scan does not find). It posts to the webhook in FILE (a Mattermost incoming webhook) when one is within
--warn-days of expiry or past it, repeats hourly while that holds, and posts once when it clears.
A credential with no expiry (a JWT with no exp, such as a non-expiring service-account token or an
offline refresh token) is reported as such and never pages. A credential whose expiry cannot be
read (an exec plugin, a certificate file reference, an unreadable file, a JWT whose exp is not a
number) pages: this check cannot see it. An opaque token (not a JWT) is reported as of unknown
lifetime and does not page: its lifetime is its provider's, and nothing on the machine could clear
the page. STATE records only what was delivered, so an undelivered post is tried again next run.
Exit 1 when a post could not be delivered.

SECRETS. The webhook URL is read from FILE and sent only to urllib; no part of it is ever printed
(TXE-7313). A URL that is not a well-formed https URL urllib can post to is refused when FILE is
read, before any post, and --check-webhook (the installers' check) refuses it the same way. Every
failure to build or deliver a post is reported by its class alone: nothing urllib or http.client
raises is printed, because its message or traceback can hold the URL. Tokens are decoded only to
read their exp claim; no token, other claim or certificate body is printed.
"""
import argparse
import base64
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

REPEAT_SECONDS = 3600
# Cloudflare in front of the Mattermost host answers 403 to urllib's default "Python-urllib/3.x".
USER_AGENT = "txe-dagu-credential-watch/1 (TXE-7226)"


def jwt_expiry(token):
    """("jwt", exp or None) for a JWT; ("unknown", None) for a JWT whose exp is not a number;
    ("opaque", None) for anything that is not a JWT. Reads only exp."""
    parts = token.split(".")
    if len(parts) != 3:
        return "opaque", None
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return "opaque", None
    if not isinstance(claims, dict):
        return "opaque", None
    exp = claims.get("exp")
    if exp in (None, 0):
        return "jwt", None
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        # A JWT that names an expiry this cannot read: that pages, as any unreadable expiry does.
        return "unknown", None
    return "jwt", float(exp)


def cert_expiry(pem):
    """notAfter of a PEM certificate, through openssl; raises ValueError if it cannot be read."""
    r = subprocess.run(["openssl", "x509", "-noout", "-enddate"], input=pem, capture_output=True, timeout=10)
    line = r.stdout.decode("ascii", "replace").strip()
    if r.returncode != 0 or not line.startswith("notAfter="):
        raise ValueError("openssl could not read the certificate")
    when = datetime.datetime.strptime(line[len("notAfter="):].replace(" GMT", ""), "%b %d %H:%M:%S %Y")
    return when.replace(tzinfo=datetime.timezone.utc).timestamp()


_KUBE_FIELD = re.compile(r'^\s*(token|client-certificate-data):\s*["\']?([^"\'\s]+)["\']?\s*$')


def _credential(field, value):
    """(what, kind, expiry) for one kubeconfig credential field."""
    if field == "token":
        kind, exp = jwt_expiry(value)
        return ("kubeconfig token", kind, exp)
    try:
        return ("kubeconfig client certificate", "x509", cert_expiry(base64.b64decode(value)))
    except (ValueError, OSError, subprocess.SubprocessError):
        return ("kubeconfig client certificate", "unknown", None)


def _json_kubeconfig(text):
    """The credentials of a JSON kubeconfig (tunnel-credential.sh writes JSON), or None when the
    text is not JSON."""
    try:
        config = json.loads(text)
    except ValueError:
        return None
    if not isinstance(config, dict):
        return None
    found = []
    for entry in config.get("users") or []:
        user = entry.get("user") if isinstance(entry, dict) else None
        if not isinstance(user, dict):
            continue
        for field in ("token", "client-certificate-data"):
            if isinstance(user.get(field), str) and user[field]:
                found.append(_credential(field, user[field]))
        for field in ("exec", "client-certificate", "auth-provider"):
            if user.get(field):
                found.append(("kubeconfig " + field, "unknown", None))
    return found


def kubeconfig_credentials(text):
    """[(what, kind, expiry or None)] for every token and inline client certificate in a kubeconfig.

    JSON (what tunnel-credential.sh writes) is read as JSON. Anything else goes through a line
    parser, not YAML: a kubeconfig's credential fields are single scalars, and the machine's python
    may have no YAML module. An exec plugin or a certificate file reference is reported as
    "unknown", which pages: this check cannot see that credential's expiry."""
    found = _json_kubeconfig(text)
    if found is not None:
        return found
    found = []
    for line in text.splitlines():
        m = _KUBE_FIELD.match(line)
        if not m:
            if re.match(r'^\s*(exec|client-certificate|auth-provider):', line):
                found.append(("kubeconfig " + line.strip().split(":")[0], "unknown", None))
            continue
        found.append(_credential(*m.groups()))
    return found


def _refresh_token(path, name):
    """(name, kind, expiry, problem) for a credential file's refresh token."""
    try:
        with open(path) as f:
            data = json.load(f)
        token = data["refresh_token"]
        if not isinstance(token, str):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        return (name, "unknown", None, "unreadable or has no refresh_token")
    kind, exp = jwt_expiry(token)
    # An opaque refresh token's lifetime is the provider's and nothing here can read it, so it is
    # reported as unknown but does not page: it would page hourly with nothing on the machine
    # able to clear it (TXE-7226). A JWT with an unreadable exp does page.
    return (name + " refresh token", kind, exp, "expiry unknown" if kind == "unknown" else None)


def machine_credentials(home, extra=()):
    """[(name, kind, expiry or None, problem or None)] for every credential under a TXE Dagu home,
    and for each file in extra that the scan of the home did not already read."""
    out = []
    kube = os.path.join(home, "tunnel", "kubeconfig")
    if os.path.exists(kube):
        try:
            with open(kube) as f:
                entries = kubeconfig_credentials(f.read())
        except OSError as e:
            out.append(("tunnel/kubeconfig", "unknown", None, "unreadable (%s)" % type(e).__name__))
        else:
            if not entries:
                out.append(("tunnel/kubeconfig", "unknown", None, "holds no credential this can read"))
            for what, kind, exp in entries:
                out.append(("tunnel/" + what, kind, exp, "expiry unknown" if kind == "unknown" else None))
    seen = set()
    try:
        names = sorted(os.listdir(home))
    except OSError as e:
        out.append(("TXE home", "unknown", None, "unreadable (%s)" % type(e).__name__))
        names = []
    for name in names:
        if name.endswith("-credential.json"):
            seen.add(os.path.realpath(os.path.join(home, name)))
            out.append(_refresh_token(os.path.join(home, name), name))
    for path in extra:
        if os.path.realpath(path) not in seen:
            seen.add(os.path.realpath(path))
            out.append(_refresh_token(path, path))
    return out


def credential_findings(creds, now, warn_days):
    """{key: message} for every credential that should page now."""
    findings = {}
    for name, kind, exp, problem in creds:
        if problem:
            findings[name] = "%s: %s" % (name, problem)
        elif exp is not None and exp <= now:
            findings[name] = "%s EXPIRED at %s" % (name, _utc(exp))
        elif exp is not None and exp - now <= warn_days * 86400:
            findings[name] = "%s expires at %s (in %.1f days)" % (name, _utc(exp), (exp - now) / 86400)
    return findings


def _utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def plan_posts(findings, state, now):
    """[(status, key, message, entry)]: fire a new finding, repeat one hourly, resolve a cleared one.

    entry is the state the key holds once that post is delivered (None: the key is dropped)."""
    posts = []
    for key, msg in sorted(findings.items()):
        prev = state.get(key)
        if prev is None or now - prev.get("posted", 0) >= REPEAT_SECONDS:
            posts.append(("FIRING", key, msg, {"since": prev["since"] if prev else now, "posted": now, "message": msg}))
    for key, prev in sorted(state.items()):
        if key not in findings:
            posts.append(("RESOLVED", key, "%s (was: %s)" % (key, prev.get("message", key)), None))
    return posts


def _machine_id(home):
    try:
        with open(os.path.join(home, "machine.json")) as f:
            return str(json.load(f).get("machine_id", "unknown machine"))
    except (OSError, ValueError, AttributeError):
        return "unknown machine"


def _url_problem(url):
    """Why url is not a webhook URL this watch posts to, or None.

    The answer names a class of defect, never any part of the URL. Anything urllib or http.client
    would refuse while posting is refused here instead, so it is refused at read time, before any
    post: their errors carry the URL."""
    if not url.startswith("https://"):
        return "does not hold an https URL"
    if any(not "!" <= c <= "~" for c in url):
        return "holds a malformed https URL (whitespace, a control or a non-ASCII character)"
    try:
        parts = urllib.parse.urlsplit(url)
        parts.port  # raises ValueError for a port that is not a number in range
        host = parts.hostname
        urllib.request.Request(url)
    except Exception:  # noqa: BLE001 - its message can hold the URL; the class of defect is enough
        return "holds a malformed https URL (it cannot be parsed)"
    if "@" in parts.netloc:
        return "holds a malformed https URL (it carries user credentials)"
    if not host:
        return "holds a malformed https URL (it names no host)"
    return None


def _read_webhook(path):
    """The webhook URL in path, or (None, why). No part of the URL is ever part of why."""
    try:
        with open(path) as f:
            url = f.read().strip()
    except (OSError, ValueError) as e:
        return None, "cannot read the webhook file %s (%s)" % (path, type(e).__name__)
    problem = _url_problem(url)
    if problem:
        return None, "the webhook file %s %s" % (path, problem)
    return url, None


def _send(url, text):
    """None when the webhook took the post; else why not, as a class of failure only.

    Building the request is inside the handler too, and every exception is caught: no message or
    traceback of urllib or http.client is printed, because each can hold the URL."""
    try:
        req = urllib.request.Request(url, data=json.dumps({"text": text}).encode(),
                                     headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        return "webhook answered %s" % (e.code if isinstance(e.code, int) else "an HTTP error")
    except urllib.error.URLError as e:
        # urllib wraps what failed beneath it (a refused connection, a TLS failure) in reason.
        cause = e.reason if isinstance(e.reason, BaseException) else e
        return "%s posting to the webhook" % type(cause).__name__
    except Exception as e:  # noqa: BLE001 - InvalidURL, an HTTPException, anything: its class only
        return "%s posting to the webhook" % type(e).__name__
    return None if 200 <= status < 300 else "webhook answered %d" % status


def _write_state(path, state):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".state-")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, sort_keys=True)
    os.replace(tmp, path)


def watch(args):
    home = os.path.expanduser(args.home)
    now = time.time() if args.now is None else args.now
    creds = machine_credentials(home, args.credential_file)
    for name, kind, exp, problem in creds:
        if problem or exp:
            what = problem or ("expires " + _utc(exp))
        else:
            what = "lifetime unknown (an opaque token's is the provider's)" if kind == "opaque" else "no expiry"
        print("%-44s %-7s %s" % (name, kind, what))
    findings = credential_findings(creds, now, args.warn_days)
    state = {}
    if args.state:
        try:
            with open(args.state) as f:
                state = json.load(f)
        except (OSError, ValueError):
            state = {}
        if not isinstance(state, dict):
            state = {}
    machine = _machine_id(home)
    posts = plan_posts(findings, state, now)
    url = None
    if posts and not args.dry_run:
        url, err = _read_webhook(args.webhook_file)
        if err:
            # Nothing can be delivered: the state is left as it is, so the next run tries again.
            for _, _, msg, _ in posts:
                sys.stderr.write("could not deliver (%s): %s\n" % (err, msg))
            return 1
    failed = False
    # Record only what was delivered: an undelivered page keeps the previous state, so the next
    # run tries it again.
    new_state = dict(state)
    for status, key, msg, entry in posts:
        text = "[dagu-credential-watch] [%s] %s%s: %s" % (status, (args.label + " ") if args.label else "", machine, msg)
        if args.dry_run:
            print("would post: " + text)
            continue
        err = _send(url, text)
        if err:
            failed = True
            sys.stderr.write("could not deliver (%s): %s\n" % (err, msg))
            continue
        if entry is None:
            new_state.pop(key, None)
        else:
            new_state[key] = entry
    if not args.dry_run and new_state != state:
        _write_state(args.state, new_state)
    return 1 if failed else 0


def main(argv=None):
    p = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    p.add_argument("--home", default="~/.local/share/txe-dagu", help="the TXE home")
    p.add_argument("--webhook-file", help="a file holding the webhook's https URL")
    p.add_argument("--state", help="where delivered findings are recorded")
    p.add_argument("--credential-file", action="append", default=[],
                   help="a credential file outside the home's *-credential.json scan; repeatable")
    p.add_argument("--warn-days", type=float, default=7)
    p.add_argument("--label", default="", help="text placed before the machine id, e.g. TEST")
    p.add_argument("--now", type=float, default=None, help=argparse.SUPPRESS)
    p.add_argument("--dry-run", action="store_true", help="print what would be posted; post and record nothing")
    p.add_argument("--check-webhook", metavar="FILE",
                   help="only check that FILE holds a webhook URL this posts to; exit 1 and say why when not")
    args = p.parse_args(argv)
    if args.check_webhook:
        _, err = _read_webhook(args.check_webhook)
        if err:
            sys.stderr.write(err + "\n")
            return 1
        return 0
    if not args.dry_run and not (args.webhook_file and args.state):
        p.error("--webhook-file and --state are needed unless --dry-run")
    return watch(args)


if __name__ == "__main__":
    sys.exit(main())
