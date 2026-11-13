"""Page before a worker machine's credentials expire (TXE-7226, shipped with the worker kit by TXE-7233).

The worker kit runs this on every machine it installs: hourly, through the launchd agent
com.txe.dagu-credential-watch (install.sh) or the systemd user timer
txe-dagu-credential-watch.timer (install-systemd.sh). It is the only copy of the machine-side
check; the cluster-side heartbeat watch stays in txehq/txe (ops/dagu/machine-watch.py serve).

  credential-watch.py --home HOME --webhook-file FILE --state STATE [--warn-days 7] [--label L]
  credential-watch.py --home HOME --dry-run

It finds the expiry of every credential the worker and tunnel use under HOME (the TXE home): the
tunnel kubeconfig's tokens and inline client certificates, and every *-credential.json refresh
token. It posts to the webhook in FILE (a Mattermost incoming webhook) when one is within
--warn-days of expiry or past it, repeats hourly while that holds, and posts once when it clears.
A credential with no expiry (a JWT with no exp, such as a non-expiring service-account token or an
offline refresh token) is reported as such and never pages. A credential whose expiry cannot be
read (an exec plugin, a certificate file reference, an unreadable file) pages: this check cannot
see it. STATE records only what was delivered, so an undelivered post is tried again next run.
Exit 1 when a post could not be delivered.

SECRETS. The webhook URL is read from FILE and sent only to urllib; it is never printed. Tokens are
decoded only to read their exp claim; no token, other claim or certificate body is printed.
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
import urllib.request

REPEAT_SECONDS = 3600
# Cloudflare in front of the Mattermost host answers 403 to urllib's default "Python-urllib/3.x".
USER_AGENT = "txe-dagu-credential-watch/1 (TXE-7226)"


def jwt_expiry(token):
    """("jwt", exp or None) for a JWT; ("opaque", None) for anything else. Reads only exp."""
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
        return "opaque", None
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


def kubeconfig_credentials(text):
    """[(what, kind, expiry or None)] for every token and inline client certificate in a kubeconfig.

    A line parser, not YAML: a kubeconfig's credential fields are single scalars, and the
    machine's python may have no YAML module. An exec plugin or a certificate file reference
    is reported as "unknown", which pages: this check cannot see that credential's expiry."""
    found = []
    for line in text.splitlines():
        m = _KUBE_FIELD.match(line)
        if not m:
            if re.match(r'^\s*(exec|client-certificate|auth-provider):', line):
                found.append(("kubeconfig " + line.strip().split(":")[0], "unknown", None))
            continue
        field, value = m.groups()
        if field == "token":
            kind, exp = jwt_expiry(value)
            found.append(("kubeconfig token", kind, exp))
        else:
            try:
                found.append(("kubeconfig client certificate", "x509", cert_expiry(base64.b64decode(value))))
            except (ValueError, OSError, subprocess.SubprocessError):
                found.append(("kubeconfig client certificate", "unknown", None))
    return found


def machine_credentials(home):
    """[(name, kind, expiry or None, problem or None)] for every credential under a TXE Dagu home."""
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
    try:
        names = sorted(os.listdir(home))
    except OSError as e:
        return out + [("TXE home", "unknown", None, "unreadable (%s)" % type(e).__name__)]
    for name in names:
        if not name.endswith("-credential.json"):
            continue
        try:
            with open(os.path.join(home, name)) as f:
                data = json.load(f)
            token = data["refresh_token"]
            if not isinstance(token, str):
                raise ValueError
        except (OSError, ValueError, KeyError, TypeError):
            out.append((name, "unknown", None, "unreadable or has no refresh_token"))
            continue
        kind, exp = jwt_expiry(token)
        # An opaque refresh token's lifetime is the provider's; it cannot be read here.
        out.append((name + " refresh token", kind, exp, None))
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


def _read_webhook(path):
    """The webhook URL in path, or (None, why). The URL itself is never part of a message."""
    try:
        with open(path) as f:
            url = f.read().strip()
    except OSError as e:
        return None, "cannot read the webhook file %s (%s)" % (path, type(e).__name__)
    if not url.startswith("https://"):
        return None, "the webhook file %s does not hold an https URL" % path
    return url, None


def _send(url, text):
    req = urllib.request.Request(url, data=json.dumps({"text": text}).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return None if 200 <= resp.status < 300 else "webhook answered %d" % resp.status
    except urllib.error.HTTPError as e:
        return "webhook answered %d" % e.code
    except OSError as e:
        return "%s posting to the webhook" % type(e).__name__


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
    creds = machine_credentials(home)
    for name, kind, exp, problem in creds:
        print("%-44s %-7s %s" % (name, kind, problem or ("expires " + _utc(exp) if exp else "no expiry")))
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
    p.add_argument("--warn-days", type=float, default=7)
    p.add_argument("--label", default="", help="text placed before the machine id, e.g. TEST")
    p.add_argument("--now", type=float, default=None, help=argparse.SUPPRESS)
    p.add_argument("--dry-run", action="store_true", help="print what would be posted; post and record nothing")
    args = p.parse_args(argv)
    if not args.dry_run and not (args.webhook_file and args.state):
        p.error("--webhook-file and --state are needed unless --dry-run")
    return watch(args)


if __name__ == "__main__":
    sys.exit(main())
