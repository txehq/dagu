"""The systemd user units of the local Dagu worker on Linux (TXE-4715): the Linux counterpart of agents.py.

Run by install-systemd.sh and uninstall-systemd.sh with `python3 -I`; it reads no environment.

  units.py write UNITS HOME KUBECTL MACHINE_ID OWNER_ID PATH TUNNEL_UNIT WORKER_UNIT
                 NAMESPACE SERVICE UI_PORT COORD_PORT CREDENTIAL_FILE PYTHON [HUB_URL]
      Write the tunnel and worker units into UNITS (a systemd user unit directory). The worker
      runs with the macOS agent's arguments; the tunnel is the same kubectl port-forward, without
      the macOS supervisor. CREDENTIAL_FILE, when not empty, is passed to the worker as
      DAGU_WORKER_AUTH_CREDENTIAL_FILE: the path only, never the contents. With an empty
      CREDENTIAL_FILE the units are exactly those of an install without one.
      Each program runs under HOME/bin/logpipe.py with PYTHON, which owns HOME/logs/worker.log or
      tunnel.log and keeps it bounded with the macOS agents' limits (TXE-5408); install-systemd.sh
      puts the script there. systemd's own stream for a unit goes to the journal and holds only
      what the wrapper itself writes to stderr, so no second descriptor is open on either log.

  units.py credential UNIT_FILE
      Print the credential file a worker unit passes, or nothing.

  units.py write-watch UNITS HOME PYTHON SERVICE TIMER WEBHOOK_FILE [CREDENTIAL_FILE]
      Write the credential-expiry watch (TXE-7233): SERVICE, a oneshot that runs
      HOME/bin/credential-watch.py under HOME/bin/logpipe.py with PYTHON, with the macOS agent's
      arguments, and TIMER, which starts it a minute after the timer starts and hourly after.
      WEBHOOK_FILE is passed as a path only, never the URL. CREDENTIAL_FILE, when not empty, is the
      worker's credential, which the watch reads too.

  units.py watch-webhook UNIT_FILE
      Print the webhook file a watch service passes, or nothing.

The machine credential itself is checked by agents.py check-credential, shared with macOS.
"""
import contextlib, os, sys

CREDENTIAL_ENV = "DAGU_WORKER_AUTH_CREDENTIAL_FILE"


def _quote(word, exec_line):
    """One word for ExecStart= (exec_line) or Environment=, as systemd.syntax and systemd.exec read
    them: double-quoted, with backslash and double quote escaped and % doubled (specifiers are
    expanded in both). $ is doubled only on ExecStart=, which expands variables; Environment= does
    not, and keeps "$$" as two dollars (measured on Ubuntu 24.04's systemd 255)."""
    if any(c in word for c in "\n\r\0"):
        raise ValueError(f"a unit value cannot hold a line break or NUL: {word!r}")
    word = word.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if exec_line:
        word = word.replace("$", "$$")
    return '"' + word + '"'


# A unit's stop, in seconds. STOP_WAIT_S is how long the wrapper waits for its child after
# passing on the stop signal before it kills it: the 90 s systemd gives a unit by default, which
# is what the worker had to finish its tasks when the unit ran it directly. The unit then gets
# STOP_MARGIN_S more, for the wrapper to drain what a descendant still writes (5 s at most)
# and to end its compression.
STOP_WAIT_S, STOP_MARGIN_S = 90, 15


def _logged(python, home, stem, max_bytes, backups, argv):
    """argv under logpipe.py, which owns HOME/logs/STEM.log and bounds it (TXE-4724)."""
    return [python, "-I", f"{home}/bin/logpipe.py", "--path", f"{home}/logs/{stem}.log",
            "--max-bytes", str(max_bytes), "--backups", str(backups),
            "--kill-timeout", str(STOP_WAIT_S), "--", *argv]


def _unit(description, argv, environment):
    lines = ["[Unit]", f"Description={description}", "After=network-online.target", "",
             "[Service]", "Type=simple"]
    lines += [f"Environment={_quote(f'{k}={v}', False)}" for k, v in environment.items()]
    lines += ["ExecStart=" + " ".join(_quote(a, True) for a in argv),
              # As launchd's KeepAlive with ThrottleInterval 5: always restarted, 5 s apart.
              "Restart=always", "RestartSec=5",
              # Stop as launchd stops an agent: SIGTERM to the wrapper alone, which passes it to
              # its child alone, so the worker stops its steps itself and each gets its stop
              # signal once; whatever is left of the control group when the wrapper exits is
              # killed. Under the default, control-group, systemd also signals every process
              # itself: the worker and each step then get SIGTERM twice (measured, systemd 255).
              "KillMode=mixed", f"TimeoutStopSec={STOP_WAIT_S + STOP_MARGIN_S}",
              # The wrapper exits 143 when SIGTERM ended its child, as it ends kubectl. systemd
              # counts a main process ended by SIGTERM as stopped, not failed; so is this code.
              "SuccessExitStatus=143",
              "StandardOutput=journal", "StandardError=journal", "SyslogIdentifier=%N", "",
              "[Install]", "WantedBy=default.target", ""]
    return "\n".join(lines)


def write_units(units, home, kubectl, machine_id, owner_id, path, tunnel_unit, worker_unit,
                namespace, service, ui_port, coord_port, credential_file, python, hub_url=""):
    checked = [("the TXE home", home), ("python3", python)] + ([] if hub_url else [("kubectl", kubectl)])
    for name, value in checked:
        if not os.path.isabs(value):
            raise ValueError(f"{name} must be an absolute path for a unit, got {value!r}")
    # The log limits are the macOS agents' (agents.py); txe/worker's tests hold the two together.
    tunnel = _unit("TXE Dagu tunnel to the hub (kubectl port-forward, loopback only)",
                   _logged(python, home, "tunnel", 8388608, 5, [
                       kubectl, "--kubeconfig", f"{home}/tunnel/kubeconfig", "-n", namespace,
                       "port-forward", "--address", "127.0.0.1", service,
                       f"{ui_port}:8080", f"{coord_port}:{coord_port}"]), {"PATH": path})
    environment = {"DAGU_HOME": f"{home}/worker-home", "PATH": path}
    if credential_file:
        environment[CREDENTIAL_ENV] = credential_file
    worker = _unit(f"TXE Dagu worker {machine_id}", _logged(python, home, "worker", 67108864, 10, [
        f"{home}/bin/dagu", "worker",
        "--worker.id", machine_id,
        "--worker.labels", f"txe.machine={machine_id},txe.owner={owner_id}",
        *(["--worker.hub-url", hub_url] if hub_url else ["--worker.coordinators", f"127.0.0.1:{coord_port}"])]),
        environment)
    os.makedirs(units, exist_ok=True)
    # On the worker channel there is no tunnel, and a tunnel left behind would keep a
    # Kubernetes credential in use.
    if hub_url:
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(units, tunnel_unit))
    for name, body in (((worker_unit, worker),) if hub_url else ((tunnel_unit, tunnel), (worker_unit, worker))):
        target = os.path.join(units, name)
        tmp = target + ".tmp"
        with open(tmp, "w") as f:
            f.write(body)
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)


# The macOS watch agent's limits (agents.py); txe/worker's tests hold the two together.
WATCH_INTERVAL_S = 3600
WATCH_LOG_MAX_BYTES, WATCH_LOG_BACKUPS = 1048576, 3
# logpipe.py needs --max-bytes at least four chunks; its default chunk, 1 MiB, is the worker's.
WATCH_LOG_CHUNK_BYTES = 65536
# A run reads a few files and makes a post per finding, each bounded to 15 s; this bounds a hung one.
WATCH_TIMEOUT_S = 300


def watch_service(python, home, webhook_file, credential_file=""):
    argv = [python, "-I", f"{home}/bin/logpipe.py", "--path", f"{home}/logs/credential-watch.log",
            "--max-bytes", str(WATCH_LOG_MAX_BYTES), "--backups", str(WATCH_LOG_BACKUPS),
            "--chunk-bytes", str(WATCH_LOG_CHUNK_BYTES), "--",
            python, "-I", f"{home}/bin/credential-watch.py", "--home", home,
            "--webhook-file", webhook_file, "--state", f"{home}/credential-watch/state.json",
            *(["--credential-file", credential_file] if credential_file else [])]
    return "\n".join(["[Unit]", "Description=TXE Dagu credential-expiry watch",
                      "After=network-online.target", "",
                      "[Service]", "Type=oneshot",
                      "ExecStart=" + " ".join(_quote(a, True) for a in argv),
                      f"TimeoutStartSec={WATCH_TIMEOUT_S}",
                      "StandardOutput=journal", "StandardError=journal", "SyslogIdentifier=%N", ""])


def watch_timer(service):
    return "\n".join(["[Unit]", "Description=Run the TXE Dagu credential-expiry watch hourly", "",
                      "[Timer]",
                      # A minute after the timer starts (the install, each boot or login), as
                      # launchd's RunAtLoad; then an hour after each run, as its StartInterval.
                      "OnActiveSec=60", f"OnUnitActiveSec={WATCH_INTERVAL_S}", "AccuracySec=60",
                      f"Unit={service}", "",
                      "[Install]", "WantedBy=timers.target", ""])


def write_watch(units, home, python, service, timer, webhook_file, credential_file=""):
    for name, value in (("the TXE home", home), ("python3", python), ("the webhook file", webhook_file)):
        if not os.path.isabs(value):
            raise ValueError(f"{name} must be an absolute path for a unit, got {value!r}")
    bodies = ((service, watch_service(python, home, webhook_file, credential_file)), (timer, watch_timer(service)))
    os.makedirs(units, exist_ok=True)
    for name, body in bodies:
        target = os.path.join(units, name)
        with open(target + ".tmp", "w") as f:
            f.write(body)
        os.chmod(target + ".tmp", 0o644)
        os.replace(target + ".tmp", target)


def _exec_words(value):
    """The words of an ExecStart= value _quote wrote, unescaped."""
    words, i = [], 0
    while i < len(value):
        if value[i] == " ":
            i += 1
            continue
        if value[i] != '"':
            raise ValueError("not a quoted word")
        word, i = [], i + 1
        while i < len(value) and value[i] != '"':
            c = value[i]
            if c == "\\" or c in "%$":
                i += 1
                c = value[i] if c == "\\" else c
            word.append(c)
            i += 1
        words.append("".join(word))
        i += 1
    return words


def unit_webhook(unit_file):
    """The webhook file a watch service passes, or None."""
    try:
        lines = open(unit_file).read().splitlines()
    except FileNotFoundError:
        return None
    for line in lines:
        if line.startswith("ExecStart="):
            words = _exec_words(line[len("ExecStart="):])
            if "--webhook-file" in words[:-1]:
                return words[words.index("--webhook-file") + 1]
    return None


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
            return raw.replace("%%", "%").replace('\\"', '"').replace("\\\\", "\\")
    return None


def main(argv):
    if len(argv) in (15, 16) and argv[0] == "write":
        try:
            write_units(*argv[1:])
        except ValueError as e:
            print(f"units refused: {e}", file=sys.stderr)
            return 1
        return 0
    if len(argv) in (7, 8) and argv[0] == "write-watch":
        try:
            write_watch(*argv[1:])
        except ValueError as e:
            print(f"units refused: {e}", file=sys.stderr)
            return 1
        return 0
    if len(argv) == 2 and argv[0] == "watch-webhook":
        value = unit_webhook(argv[1])
        if value:
            print(value)
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
