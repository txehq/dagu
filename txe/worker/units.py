"""The systemd user units of the local Dagu worker on Linux (TXE-4715): the Linux counterpart of agents.py.

Run by install-systemd.sh and uninstall-systemd.sh with `python3 -I`; it reads no environment.

  units.py write UNITS HOME KUBECTL MACHINE_ID OWNER_ID PATH TUNNEL_UNIT WORKER_UNIT
                 NAMESPACE SERVICE UI_PORT COORD_PORT CREDENTIAL_FILE
      Write the tunnel and worker units into UNITS (a systemd user unit directory). They run the same
      programs with the same arguments as the macOS agents. CREDENTIAL_FILE, when not empty, is
      passed to the worker as DAGU_WORKER_AUTH_CREDENTIAL_FILE: the path only, never the contents.
      With an empty CREDENTIAL_FILE the units are exactly those of an install without one.

  units.py credential UNIT_FILE
      Print the credential file a worker unit passes, or nothing.

The machine credential itself is checked by agents.py check-credential, shared with macOS.
"""
import os, sys

CREDENTIAL_ENV = "DAGU_WORKER_AUTH_CREDENTIAL_FILE"


def _quote(word):
    """One word for ExecStart= or Environment=, as systemd.syntax reads it: double-quoted, with
    backslash and double quote escaped, % doubled (specifiers) and $ doubled (variable expansion)."""
    if any(c in word for c in "\n\r\0"):
        raise ValueError(f"a unit value cannot hold a line break or NUL: {word!r}")
    return '"' + word.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def _unit(description, argv, environment, log):
    lines = ["[Unit]", f"Description={description}", "After=network-online.target", "",
             "[Service]", "Type=simple"]
    lines += [f"Environment={_quote(f'{k}={v}')}" for k, v in environment.items()]
    lines += ["ExecStart=" + " ".join(_quote(a) for a in argv),
              # As launchd's KeepAlive with ThrottleInterval 5: always restarted, 5 s apart.
              "Restart=always", "RestartSec=5",
              f"StandardOutput=append:{log}", f"StandardError=append:{log}", "",
              "[Install]", "WantedBy=default.target", ""]
    for p in (log,):
        if any(c in p for c in " \t\n%$\"\\"):
            raise ValueError(f"the log path must have no space or special character for StandardOutput=append: {p!r}")
    return "\n".join(lines)


def write_units(units, home, kubectl, machine_id, owner_id, path, tunnel_unit, worker_unit,
                namespace, service, ui_port, coord_port, credential_file):
    tunnel = _unit("TXE Dagu tunnel to the hub (kubectl port-forward, loopback only)", [
        kubectl, "--kubeconfig", f"{home}/tunnel/kubeconfig", "-n", namespace,
        "port-forward", "--address", "127.0.0.1", service,
        f"{ui_port}:8080", f"{coord_port}:{coord_port}"], {"PATH": path}, f"{home}/logs/tunnel.log")
    environment = {"DAGU_HOME": f"{home}/worker-home", "PATH": path}
    if credential_file:
        environment[CREDENTIAL_ENV] = credential_file
    worker = _unit(f"TXE Dagu worker {machine_id}", [
        f"{home}/bin/dagu", "worker",
        "--worker.id", machine_id,
        "--worker.labels", f"txe.machine={machine_id},txe.owner={owner_id}",
        "--worker.coordinators", f"127.0.0.1:{coord_port}"], environment, f"{home}/logs/worker.log")
    os.makedirs(units, exist_ok=True)
    for name, body in ((tunnel_unit, tunnel), (worker_unit, worker)):
        target = os.path.join(units, name)
        tmp = target + ".tmp"
        with open(tmp, "w") as f:
            f.write(body)
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)


def unit_credential(unit_file):
    """The credential path a worker unit passes, or None. Reads only its own Environment= lines."""
    try:
        lines = open(unit_file).read().splitlines()
    except FileNotFoundError:
        return None
    prefix = f'Environment="{CREDENTIAL_ENV}='
    for line in lines:
        if line.startswith(prefix) and line.endswith('"'):
            raw = line[len(prefix):-1]
            return raw.replace("$$", "$").replace("%%", "%").replace('\\"', '"').replace("\\\\", "\\")
    return None


def main(argv):
    if len(argv) == 14 and argv[0] == "write":
        try:
            write_units(*argv[1:])
        except ValueError as e:
            print(f"units refused: {e}", file=sys.stderr)
            return 1
        return 0
    if len(argv) == 2 and argv[0] == "credential":
        value = unit_credential(argv[1])
        if value:
            print(value)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
