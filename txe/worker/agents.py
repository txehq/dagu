"""The launchd agents of the local Dagu worker, and the machine credential they use (TXE-4366).

Run by install.sh and status.sh with `python3 -I`; it reads no environment.

  agents.py check-credential PATH MACHINE_ID
      Exit 0 and print the file's machine and client when PATH is a machine credential
      the worker can use for MACHINE_ID; otherwise print why to stderr and exit 1.
      Nothing secret is printed: the refresh token is only checked to be present.

  agents.py write AGENTS HOME KUBECTL MACHINE_ID OWNER_ID PATH TUNNEL_LABEL WORKER_LABEL
                  NAMESPACE SERVICE UI_PORT COORD_PORT CREDENTIAL_FILE
      Write the tunnel and worker agents. CREDENTIAL_FILE, when not empty, is passed to
      the worker as DAGU_WORKER_AUTH_CREDENTIAL_FILE: the path only, never the contents.
      With an empty CREDENTIAL_FILE the agents are exactly those of an install without one.

  agents.py credential PLIST
      Print the credential file a worker agent passes, or nothing.
"""
import ipaddress, json, os, plistlib, stat, sys, urllib.parse

CREDENTIAL_ENV = "DAGU_WORKER_AUTH_CREDENTIAL_FILE"
# transportauth.MachineCredential: the worker refuses any other field.
FIELDS = {"schema", "issuer", "token_endpoint", "client_id", "class", "machine_id", "refresh_token"}


class Refused(Exception):
    pass


def _loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


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
    if data["schema"] != 1 or isinstance(data["schema"], bool):
        raise Refused(f"{path} has schema {data['schema']!r}, not 1")
    for name in FIELDS - {"schema"}:
        value = data[name]
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise Refused(f"{path}: {name} is missing or has surrounding space")
    if data["class"] != "worker":
        raise Refused(f"{path} is a {data['class']!r} credential, not a worker's")
    if data["machine_id"] != machine_id:
        raise Refused(f"{path} is for machine {data['machine_id']}, but this machine is {machine_id}")
    endpoint = urllib.parse.urlsplit(data["token_endpoint"])
    if endpoint.scheme != "https" and not (endpoint.scheme == "http" and _loopback(endpoint.hostname or "")):
        raise Refused(f"{path}: token_endpoint must use https, or http to a loopback address")
    return data["machine_id"], data["client_id"]


def write_agents(agents, home, kubectl, machine_id, owner_id, path, tunnel_label, worker_label,
                 namespace, service, ui_port, coord_port, credential_file):
    common = {"RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 5,
              "ProcessType": "Background"}
    tunnel = dict(common, Label=tunnel_label, ProgramArguments=[
        kubectl, "--kubeconfig", f"{home}/tunnel/kubeconfig", "-n", namespace,
        "port-forward", "--address", "127.0.0.1", service,
        f"{ui_port}:8080", f"{coord_port}:{coord_port}"],
        StandardOutPath=f"{home}/logs/tunnel.log", StandardErrorPath=f"{home}/logs/tunnel.log")
    environment = {"DAGU_HOME": f"{home}/worker-home", "PATH": path}
    if credential_file:
        environment[CREDENTIAL_ENV] = credential_file
    worker = dict(common, Label=worker_label, ProgramArguments=[
        f"{home}/bin/dagu", "worker",
        "--worker.id", machine_id,
        "--worker.labels", f"txe.machine={machine_id},txe.owner={owner_id}",
        "--worker.coordinators", f"127.0.0.1:{coord_port}"],
        EnvironmentVariables=environment,
        WorkingDirectory=f"{home}/worker-home",
        StandardOutPath=f"{home}/logs/worker.log", StandardErrorPath=f"{home}/logs/worker.log")
    for label, body in ((tunnel_label, tunnel), (worker_label, worker)):
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
    if len(argv) == 14 and argv[0] == "write":
        write_agents(*argv[1:])
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
