"""The launchd agents of the local Dagu worker, and the machine credential they use (TXE-4366).

Run by install.sh and status.sh with `python3 -I`; it reads no environment.

  agents.py check-credential PATH MACHINE_ID
      Exit 0 and print the file's machine and client when PATH is a machine credential
      the worker can use for MACHINE_ID; otherwise print why to stderr and exit 1.
      This is install.sh's early check, before the build; the built binary's
      `dagu txe enrol check` (the worker's own loader) decides before any agent is written.
      Nothing secret is printed: the refresh token is only checked to be present.

  agents.py write AGENTS HOME KUBECTL MACHINE_ID OWNER_ID PATH TUNNEL_LABEL WORKER_LABEL
                  NAMESPACE SERVICE UI_PORT COORD_PORT CREDENTIAL_FILE PYTHON
      Write the tunnel and worker agents. CREDENTIAL_FILE, when not empty, is passed to
      the worker as DAGU_WORKER_AUTH_CREDENTIAL_FILE: the path only, never the contents.
      With an empty CREDENTIAL_FILE the agents are exactly those of an install without one.
      The tunnel agent runs HOME/tunnel/tunnel-supervise.py with PYTHON, and kubectl under it
      (TXE-5398); the worker agent runs HOME/bin/logpipe.py with PYTHON, and the worker under
      it, so logs/worker.log stays bounded (TXE-4724); install.sh puts both scripts there.

  agents.py credential PLIST
      Print the credential file a worker agent passes, or nothing.

  agents.py write-watch AGENTS HOME PYTHON LABEL WEBHOOK_FILE
      Write the credential-expiry watch's agent (TXE-7233): HOME/bin/credential-watch.py, run
      hourly and at load under HOME/bin/logpipe.py with PYTHON, posting through the webhook in
      WEBHOOK_FILE (the path only, never the URL). install.sh puts both scripts there.

  agents.py watch-webhook PLIST
      Print the webhook file a watch agent passes, or nothing. It reads the agent the
      hand-installed watch of TXE-7226 used as well, so an install keeps its webhook.
"""
import contextlib, ipaddress, json, os, plistlib, re, stat, sys, urllib.parse

CREDENTIAL_ENV = "DAGU_WORKER_AUTH_CREDENTIAL_FILE"
# transportauth.MachineCredential: the worker refuses any other field.
FIELDS = {"schema", "issuer", "token_endpoint", "client_id", "class", "machine_id", "refresh_token"}


class Refused(Exception):
    pass


def _loopback(host):
    # As transportauth's isLoopback: "localhost" exactly, or a loopback IP.
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _endpoint_host(netloc):
    """The host of an authority with no user info, brackets removed, case kept (as Go's Hostname)."""
    if netloc.startswith("["):
        end = netloc.find("]")
        return netloc[1:end] if end > 0 else ""
    return netloc.rsplit(":", 1)[0] if ":" in netloc else netloc


def _check_endpoint(path, raw):
    # The worker loads the file with transportauth.MachineCredential.Validate: an absolute URL with
    # a host, no user info and no fragment; https, or http to a loopback address.
    try:
        endpoint = urllib.parse.urlsplit(raw)
        endpoint.port  # a malformed port raises
    except ValueError:
        raise Refused(f"{path}: token_endpoint is not an absolute URL")
    if not endpoint.netloc or "@" in endpoint.netloc or endpoint.fragment or not endpoint.scheme:
        raise Refused(f"{path}: token_endpoint is not an absolute URL")
    # Go's url.Parse refuses a malformed percent-escape in the host or the path.
    if _BAD_ESCAPE.search(endpoint.netloc + endpoint.path):
        raise Refused(f"{path}: token_endpoint is not an absolute URL")
    host = _endpoint_host(endpoint.netloc)
    if not host:
        raise Refused(f"{path}: token_endpoint is not an absolute URL")
    if endpoint.scheme != "https" and not (endpoint.scheme == "http" and _loopback(host)):
        raise Refused(f"{path}: token_endpoint must use https, or http to a loopback address")


def check_credential(path, machine_id):
    """Return (machine_id, client_id) of a usable credential at path, or raise Refused."""
    if not os.path.isabs(path):
        raise Refused(f"{path!r} is not an absolute path")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise Refused(f"{path} does not exist; run `dagu txe enrol` first, or give the file it wrote")
    if stat.S_ISLNK(st.st_mode):
        raise Refused(f"{path} is a symlink; give the credential file itself")
    if not stat.S_ISREG(st.st_mode):
        raise Refused(f"{path} is not a regular file")
    if st.st_uid != os.getuid():
        raise Refused(f"{path} is not owned by this user")
    if st.st_mode & 0o077:
        raise Refused(f"{path} has mode {stat.S_IMODE(st.st_mode):#o}; it must be readable by its owner only (0600)")
    # The worker rewrites the file when the provider rotates the refresh token and keeps
    # <path>.lock beside it, so the directory must be this user's and writable by it, and
    # no one else may replace the file in it.
    directory = os.path.dirname(path)
    dst = os.stat(directory)
    if dst.st_uid != os.getuid() or dst.st_mode & 0o022:
        raise Refused(f"{directory} must be owned by this user and writable by no one else")
    if not os.access(directory, os.W_OK | os.X_OK):
        raise Refused(f"{directory} is not writable by this user; the worker saves rotated tokens there")
    try:
        with open(path, "rb") as f:
            data = json.loads(f.read())
    except (OSError, ValueError):
        raise Refused(f"{path} is not a readable JSON machine credential")
    if not isinstance(data, dict):
        raise Refused(f"{path} is not a JSON object")
    if set(data) != FIELDS:
        missing, extra = sorted(FIELDS - set(data)), sorted(set(data) - FIELDS)
        raise Refused(f"{path} does not hold exactly the machine credential fields (missing {missing}, unexpected {extra})")
    # Go decodes schema into an int: 1.0 or "1" do not load.
    if type(data["schema"]) is not int or data["schema"] != 1:
        raise Refused(f"{path} has schema {data['schema']!r}, not the integer 1")
    for name in FIELDS - {"schema"}:
        value = data[name]
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise Refused(f"{path}: {name} is missing or has surrounding space")
    if data["class"] != "worker":
        raise Refused(f"{path} is a {data['class']!r} credential, not a worker's")
    if data["machine_id"] != machine_id:
        raise Refused(f"{path} is for machine {data['machine_id']}, but this machine is {machine_id}")
    _check_endpoint(path, data["token_endpoint"])
    return data["machine_id"], data["client_id"]


def check_hub_url(raw):
    """Refuse a hub address that could send the machine's credential anywhere unsafe."""
    try:
        hub = urllib.parse.urlsplit(raw)
        hub.port  # a malformed port raises
    except ValueError:
        raise Refused(f"{raw!r} is not a URL")
    host = _endpoint_host(hub.netloc)
    if not host or "@" in hub.netloc or hub.query or hub.fragment:
        raise Refused(f"{raw!r} must be an address with no user, query or fragment")
    if hub.scheme != "https" and not (hub.scheme == "http" and _loopback(host)):
        raise Refused(f"{raw!r} must use https, or http to a loopback address")


def hub_health(raw):
    """The health URL of a hub address, by the worker's rule: a path names the API root."""
    hub = urllib.parse.urlsplit(raw)
    root = hub.path.rstrip("/") or "/api/v1"
    return urllib.parse.urlunsplit((hub.scheme, hub.netloc, f"{root}/health", "", ""))


def write_agents(agents, home, kubectl, machine_id, owner_id, path, tunnel_label, worker_label,
                 namespace, service, ui_port, coord_port, credential_file, python, hub_url=""):
    common = {"RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 5,
              "ProcessType": "Background"}
    # launchd restarts the tunnel only when it exits, and a port-forward whose connection is
    # dead can keep running, so the supervisor ends it when its streams and the worker's
    # heartbeats have both failed long enough (TXE-5398), or its new streams alone have failed
    # for --streams-only-after (TXE-6144).
    tunnel = dict(common, Label=tunnel_label, ProgramArguments=[
        python, "-I", f"{home}/bin/logpipe.py",
        "--path", f"{home}/logs/tunnel.log", "--max-bytes", "8388608", "--backups", "5", "--",
        python, "-I", f"{home}/tunnel/tunnel-supervise.py",
        "--ui-port", ui_port, "--coord-port", coord_port,
        "--worker-log", f"{home}/logs/worker.log", "--state", f"{home}/tunnel/supervise-state.json", "--",
        kubectl, "--kubeconfig", f"{home}/tunnel/kubeconfig", "-n", namespace,
        "port-forward", "--address", "127.0.0.1", service,
        f"{ui_port}:8080", f"{coord_port}:{coord_port}"],
        StandardOutPath=f"{home}/logs/tunnel.launchd.log", StandardErrorPath=f"{home}/logs/tunnel.launchd.log")
    environment = {"DAGU_HOME": f"{home}/worker-home", "PATH": path}
    if credential_file:
        environment[CREDENTIAL_ENV] = credential_file
    # The worker's output goes through logpipe.py, which owns logs/worker.log and keeps it
    # bounded (TXE-4724); launchd's own file for this agent holds only the wrapper's
    # diagnostics, so no second descriptor on worker.log can defeat the bound.
    worker = dict(common, Label=worker_label, ProgramArguments=[
        python, "-I", f"{home}/bin/logpipe.py",
        "--path", f"{home}/logs/worker.log", "--max-bytes", "67108864", "--backups", "10", "--",
        f"{home}/bin/dagu", "worker",
        "--worker.id", machine_id,
        "--worker.labels", f"txe.machine={machine_id},txe.owner={owner_id}",
        *(["--worker.hub-url", hub_url] if hub_url else ["--worker.coordinators", f"127.0.0.1:{coord_port}"])],
        EnvironmentVariables=environment,
        WorkingDirectory=f"{home}/worker-home",
        StandardOutPath=f"{home}/logs/worker.launchd.log", StandardErrorPath=f"{home}/logs/worker.launchd.log")
    # On the worker channel there is no tunnel, and a tunnel left behind would keep a
    # Kubernetes credential in use.
    if hub_url:
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(agents, f"{tunnel_label}.plist"))
    for label, body in (((worker_label, worker),) if hub_url else ((tunnel_label, tunnel), (worker_label, worker))):
        target = os.path.join(agents, f"{label}.plist")
        with open(target + ".tmp", "wb") as f:
            plistlib.dump(body, f)
        os.replace(target + ".tmp", target)


# The watch's own limits: one run an hour writes a few lines, so 1 MiB holds months of them.
WATCH_INTERVAL_S = 3600
WATCH_LOG_MAX_BYTES, WATCH_LOG_BACKUPS = 1048576, 3
# logpipe.py needs --max-bytes at least four chunks; its default chunk, 1 MiB, is the worker's.
WATCH_LOG_CHUNK_BYTES = 65536


def watch_arguments(python, home, webhook_file):
    """The watch's command: credential-watch.py under logpipe.py, which bounds its log."""
    return [python, "-I", f"{home}/bin/logpipe.py",
            "--path", f"{home}/logs/credential-watch.log",
            "--max-bytes", str(WATCH_LOG_MAX_BYTES), "--backups", str(WATCH_LOG_BACKUPS),
            "--chunk-bytes", str(WATCH_LOG_CHUNK_BYTES), "--",
            python, "-I", f"{home}/bin/credential-watch.py", "--home", home,
            "--webhook-file", webhook_file, "--state", f"{home}/credential-watch/state.json"]


def write_watch(agents, home, python, label, webhook_file):
    for name, value in (("the TXE home", home), ("python3", python), ("the webhook file", webhook_file)):
        if not os.path.isabs(value):
            raise Refused(f"{name} must be an absolute path, got {value!r}")
    body = {"Label": label, "ProgramArguments": watch_arguments(python, home, webhook_file),
            # Runs at load and then hourly; it is not kept alive: each run checks and exits.
            "RunAtLoad": True, "StartInterval": WATCH_INTERVAL_S, "ProcessType": "Background",
            "WorkingDirectory": home,
            "StandardOutPath": f"{home}/logs/credential-watch.launchd.log",
            "StandardErrorPath": f"{home}/logs/credential-watch.launchd.log"}
    target = os.path.join(agents, f"{label}.plist")
    with open(target + ".tmp", "wb") as f:
        plistlib.dump(body, f)
    os.replace(target + ".tmp", target)


def main(argv):
    if len(argv) == 3 and argv[0] == "check-credential":
        try:
            machine, client = check_credential(argv[1], argv[2])
        except Refused as e:
            print(f"machine credential refused: {e}", file=sys.stderr)
            return 1
        print(f"credential {argv[1]} (machine {machine}, client {client})")
        return 0
    if len(argv) == 2 and argv[0] == "check-hub-url":
        try:
            check_hub_url(argv[1])
        except Refused as e:
            print(f"hub address refused: {e}", file=sys.stderr)
            return 1
        return 0
    if len(argv) == 2 and argv[0] == "hub-health":
        print(hub_health(argv[1]))
        return 0
    if len(argv) in (15, 16) and argv[0] == "write":
        write_agents(*argv[1:])
        return 0
    if len(argv) == 2 and argv[0] == "hub-url":
        try:
            with open(argv[1], "rb") as f:
                arguments = plistlib.load(f).get("ProgramArguments", [])
        except FileNotFoundError:
            return 0
        if "--worker.hub-url" in arguments:
            print(arguments[arguments.index("--worker.hub-url") + 1])
        return 0
    if len(argv) == 6 and argv[0] == "write-watch":
        try:
            write_watch(*argv[1:])
        except Refused as e:
            print(f"watch agent refused: {e}", file=sys.stderr)
            return 1
        return 0
    if len(argv) == 2 and argv[0] == "watch-webhook":
        try:
            with open(argv[1], "rb") as f:
                arguments = plistlib.load(f).get("ProgramArguments", [])
        except FileNotFoundError:
            return 0
        if "--webhook-file" in arguments[:-1]:
            print(arguments[arguments.index("--webhook-file") + 1])
        return 0
    if len(argv) == 2 and argv[0] == "credential":
        try:
            with open(argv[1], "rb") as f:
                body = plistlib.load(f)
        except FileNotFoundError:
            return 0
        value = body.get("EnvironmentVariables", {}).get(CREDENTIAL_ENV)
        if value:
            print(value)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
