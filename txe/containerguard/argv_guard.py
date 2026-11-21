# SPDX-License-Identifier: GPL-3.0-or-later
"""One shared positional guard for a container runner's `docker create` argv (TXE-8041).

Extracted from the guard TXE-8039 validated (runner-kg-r3.py, receipt bb7e127e). It replaces the
joined-substring check that container runners copied from runner-final: that check searched the
whole argv as one space-joined string, so text inside a reviewed command payload (`command -v`,
`go test -v`) read as Docker's -v, and an option it did not list passed.

The guard checks ONE shape, ["create", <options>, image, <payload tokens>], against a Schema that
spells out one run's exact argv:

- check_schema(schema) is the POLICY FLOOR, which no consumer can loosen. It is STRUCTURAL:
  - every path is absolute and already normalised;
  - the work dir lies strictly inside scratch;
  - a mount is the canonical `type=bind,source=..,target=..[,readonly]` with no alias or
    duplicate key, its source strictly inside the work dir, its target outside the kernel and
    runtime trees, unique, and read-only unless the schema declares that target writable;
  - nothing is mounted from or onto a Docker socket or the runtime directories;
  - --network none, --pull never, --cap-drop ALL, --security-opt no-new-privileges and
    --read-only are fixed;
  - the user is not root;
  - the image is an immutable digest;
  - env and label keys are well formed and unique, and env names that carry credentials by
    convention, or point at a Docker daemon or an SSH agent, are refused;
  - an option belongs to exactly one kind (flag, single or repeated).

  A value is not proven secret-free by its text: the env set must equal the reviewed schema, and
  the schema is reviewed source.
- violations(argv, schema) reads OPTIONS by position, as tokens up to the image. Each option must
  be in the schema with its exact value, once (a repeated option's values must equal its set). A
  denied option, an --opt=value form or any option outside the schema refuses and stops parsing,
  failing closed. The image must be the schema's, right after the schema's last option. The
  PAYLOAD tokens must equal the schema's exactly: they are compared whole, never parsed. The argv
  is never joined.

Diagnostics are REDACTED. A Violation holds a stable code, an option name only when it is a KNOWN
constant (a schema option or a denied one), a position, and counts. It never holds a value or an
unknown token from the argv or the schema, so an unexpected `--env NAME=<credential>` or
`--x=<credential>` is reported without it.

This is a validator of a fixed, reviewed argv. It is NOT a safe logger of arbitrary argv, and its
callers must not print the argv they refuse.
"""
import posixpath
import re
from dataclasses import dataclass, field

DENIED_OPTIONS = frozenset({
    "-v", "--volume", "--volumes-from", "--privileged", "--cap-add", "--device", "--device-cgroup-rule",
    "--device-read-bps", "--device-write-bps", "--env-file", "-e", "--pid", "--ipc", "--uts", "--userns",
    "--cgroupns", "--cgroup-parent", "--net", "--network-alias", "-p", "--publish", "-P", "--publish-all",
    "--add-host", "--group-add", "--runtime", "--gpus", "--sysctl", "--link",
})
FLOOR_SINGLE = {"--network": "none", "--pull": "never", "--cap-drop": "ALL", "--security-opt": "no-new-privileges"}
FLOOR_FLAGS = frozenset({"--read-only"})
# The kind each policy-bearing option MUST have, so the floor's checks cannot be skipped by declaring an option in
# another kind (a --mount in `single` would bypass every mount rule). An option outside these sets may be any one kind.
REPEATED_KIND = frozenset({"--mount", "--env", "--label", "--tmpfs"})
SINGLE_KIND = frozenset(FLOOR_SINGLE) | frozenset({"--user"})
# Runtime and kernel trees that no mount may come from or go onto.
SYSTEM_TREES = ("/proc", "/sys", "/dev", "/run", "/var/run", "/var/lib/docker", "/etc", "/boot")
SOCKET_NAMES = ("docker.sock", "containerd.sock", "podman.sock")
MOUNT_KEYS = ("type", "source", "target")
ENV_KEY = re.compile(r"[A-Z_][A-Z0-9_]*")
LABEL_KEY = re.compile(r"[a-z0-9][a-z0-9._-]*")
DENIED_ENV_KEYS = frozenset({"SSH_AUTH_SOCK", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
                             "KUBECONFIG", "GOOGLE_APPLICATION_CREDENTIALS"})
CREDENTIAL_NAME = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|API_KEY|ACCESS_KEY")
IMMUTABLE_IMAGE = re.compile(r"(?:[a-z0-9][a-z0-9._/-]*@)?sha256:[0-9a-f]{64}")
ROOT_USERS = ("0", "root")

CODES = {
    "S01": "the work dir is not an absolute, normalised path strictly inside scratch",
    "S02": "a floor option is missing from the schema or has another value",
    "S03": "a floor flag is missing from the schema",
    "S04": "the schema names a denied option, an option in two kinds, or a policy option in the wrong kind",
    "S05": "a mount in the schema is not a canonical bind mount",
    "S06": "a mount source is not strictly inside the work dir",
    "S07": "a mount target is not absolute and normalised, is the root, or lies in a system tree",
    "S08": "a mount comes from or goes onto a Docker socket or runtime directory",
    "S09": "a writable mount's target is not declared writable",
    "S10": "two mounts share a target",
    "S11": "an env key is malformed, duplicated, denied, or names a credential",
    "S12": "a label key is malformed or duplicated",
    "S13": "the user is absent (the image's default) or root",
    "S14": "the image is not an immutable digest",
    "S15": "the payload is not a non-empty tuple of strings",
    "S16": "a tmpfs is not an absolute normalised path outside the system trees",
    "S17": "the schema is not well formed",
    "G01": "the argv is not a list of strings starting with create",
    "G10": "a denied option (parsing stopped)",
    "G11": "an option in --opt=value form (parsing stopped)",
    "G12": "an option outside the schema (parsing stopped)",
    "G13": "an option without its value",
    "G20": "an option's value differs from the schema",
    "G21": "an option or a repeated value is given twice",
    "G22": "a schema option is missing",
    "G23": "a repeated option's values differ from the schema's set",
    "G30": "the option before the image is not the schema's last option",
    "G31": "the token after the options is not the schema's image",
    "G32": "the payload differs from the schema's",
}


@dataclass(frozen=True)
class Schema:
    """One run's exact create argv. Every value is what this run must pass; nothing is a pattern."""
    image: str
    work_dir: str
    scratch: str
    flags: frozenset
    single: dict
    repeated: dict                   # option -> tuple of exact values (order free, each once)
    last_option: str
    payload: tuple
    writable_targets: frozenset = field(default_factory=lambda: frozenset({"/w"}))


@dataclass(frozen=True)
class Violation:
    """A redacted finding: a CODES key, a known option name or "", a position or -1, and counts."""
    code: str
    option: str = ""
    position: int = -1
    detail: str = ""

    def __str__(self):
        where = f" at position {self.position}" if self.position >= 0 else ""
        opt = f" {self.option}" if self.option else ""
        return f"{self.code}{opt}{where}{(': ' + self.detail) if self.detail else ''}"


def _known(s):
    """The option names a Violation may name: the schema's own and the denied ones (constants)."""
    names = set(DENIED_OPTIONS) | set(FLOOR_SINGLE) | set(FLOOR_FLAGS)
    if isinstance(s, Schema):
        for part in (s.flags, s.single, s.repeated):
            if isinstance(part, (dict, frozenset, set)):
                names |= {x for x in part if isinstance(x, str)}
    return names


def _say(name, known):
    return name if name in known else "<unrecognised option>"


def _normal_abs(p):
    return isinstance(p, str) and p.startswith("/") and posixpath.normpath(p) == p and "\x00" not in p


def _strictly_inside(child, parent):
    return _normal_abs(child) and _normal_abs(parent) and child != parent and \
        posixpath.commonpath([child, parent]) == parent


def _in_system_tree(p):
    return any(p == t or p.startswith(t + "/") for t in SYSTEM_TREES)


def _names_socket(p):
    return posixpath.basename(p) in SOCKET_NAMES


def _mount_fields(spec):
    """(fields, readonly) of a canonical bind spec, or None when it is not exactly that form."""
    parts = spec.split(",")
    fields, readonly = {}, False
    for i, part in enumerate(parts):
        if part == "readonly" and i == len(parts) - 1:
            readonly = True
            continue
        key, sep, val = part.partition("=")
        if not sep or key not in MOUNT_KEYS or key in fields:
            return None
        fields[key] = val
    if tuple(fields) != MOUNT_KEYS:
        return None
    return fields, readonly


def check_schema(s):
    """The policy floor: violations in the SCHEMA itself. [] when it holds."""
    if not isinstance(s, Schema) or not all(isinstance(x, (dict, frozenset, set)) for x in (s.single, s.repeated,
                                                                                          s.flags)):
        return [Violation("S17")]
    bad, known = [], _known(s)
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in s.single.items()) or \
            not all(isinstance(k, str) and isinstance(v, tuple) and all(isinstance(x, str) for x in v)
                    for k, v in s.repeated.items()) or not all(isinstance(x, str) for x in s.flags) or \
            not isinstance(s.last_option, str) or not isinstance(s.image, str):
        return [Violation("S17")]
    if not _normal_abs(s.scratch) or not _strictly_inside(s.work_dir, s.scratch):
        bad.append(Violation("S01"))
    for opt, want in FLOOR_SINGLE.items():
        if s.single.get(opt) != want:
            bad.append(Violation("S02", opt))
    for opt in sorted(FLOOR_FLAGS - set(s.flags)):
        bad.append(Violation("S03", opt))
    kinds = [set(s.flags), set(s.single), set(s.repeated)]
    for opt in sorted(set().union(*kinds)):
        if opt.split("=", 1)[0] in DENIED_OPTIONS or opt in DENIED_OPTIONS or "=" in opt or \
                sum(opt in k for k in kinds) != 1 or not opt.startswith("-") or \
                (opt in REPEATED_KIND and opt not in s.repeated) or (opt in SINGLE_KIND and opt not in s.single) or \
                (opt in FLOOR_FLAGS and opt not in s.flags):
            bad.append(Violation("S04", _say(opt, set(DENIED_OPTIONS) | set(FLOOR_SINGLE) | REPEATED_KIND |
                                             SINGLE_KIND | FLOOR_FLAGS)))
    if "--user" not in s.single or s.single["--user"].split(":", 1)[0] in ROOT_USERS + ("",):
        bad.append(Violation("S13", "--user"))     # absent means the image's user, root for most images
    if not IMMUTABLE_IMAGE.fullmatch(s.image):
        bad.append(Violation("S14"))
    if not isinstance(s.payload, tuple) or not s.payload or not all(isinstance(t, str) for t in s.payload):
        bad.append(Violation("S15"))
    targets = []
    for spec in s.repeated.get("--mount", ()):
        parsed = _mount_fields(spec)
        if parsed is None or parsed[0]["type"] != "bind":
            bad.append(Violation("S05", "--mount"))
            continue
        f, readonly = parsed
        src, dst = f["source"], f["target"]
        if not _strictly_inside(src, s.work_dir):
            bad.append(Violation("S06", "--mount"))
        if not _normal_abs(dst) or dst == "/" or _in_system_tree(dst):
            bad.append(Violation("S07", "--mount"))
        if _names_socket(src) or _names_socket(dst) or (_normal_abs(src) and _in_system_tree(src)):
            bad.append(Violation("S08", "--mount"))
        if not readonly and dst not in s.writable_targets:
            bad.append(Violation("S09", "--mount"))
        targets.append(dst)
    if len(targets) != len(set(targets)):
        bad.append(Violation("S10", "--mount"))
    keys = []
    for kv in s.repeated.get("--env", ()):
        key, sep, _ = kv.partition("=")
        keys.append(key)
        if not sep or not ENV_KEY.fullmatch(key) or key in DENIED_ENV_KEYS or CREDENTIAL_NAME.search(key):
            bad.append(Violation("S11", "--env"))
    if len(keys) != len(set(keys)):
        bad.append(Violation("S11", "--env", detail="a key is given twice"))
    lkeys = []
    for kv in s.repeated.get("--label", ()):
        key, sep, _ = kv.partition("=")
        lkeys.append(key)
        if not sep or not LABEL_KEY.fullmatch(key):
            bad.append(Violation("S12", "--label"))
    if len(lkeys) != len(set(lkeys)):
        bad.append(Violation("S12", "--label", detail="a key is given twice"))
    for spec in s.repeated.get("--tmpfs", ()):
        path = spec.split(":", 1)[0]
        if not _normal_abs(path) or path == "/" or _in_system_tree(path):
            bad.append(Violation("S16", "--tmpfs"))
    for opt, vals in s.repeated.items():
        if len(vals) != len(set(vals)):
            bad.append(Violation("S04", _say(opt, known), detail="a repeated value is listed twice"))
    return bad


def violations(argv, schema):
    """[] when argv is exactly the schema's (and the schema passes the floor); else redacted Violations.
    Never raises on any argv: a malformed one is G01."""
    bad = check_schema(schema)
    if bad and bad[0].code == "S17":
        return bad
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv) or argv[0] != "create":
        return bad + [Violation("G01")]
    s, known = schema, _known(schema)
    seen, seen_flags, seen_rep, last, i = set(), set(), {k: [] for k in s.repeated}, None, 1
    while i < len(argv) and argv[i].startswith("-"):
        tok = argv[i]
        base = tok.split("=", 1)[0]
        if base in DENIED_OPTIONS or tok in DENIED_OPTIONS:
            return bad + [Violation("G10", _say(base, known), i, "parsing stopped")]
        if "=" in tok:
            return bad + [Violation("G11", _say(base, known), i, "parsing stopped")]
        if tok in s.flags:
            if tok in seen_flags:
                bad.append(Violation("G21", tok, i))
            seen_flags.add(tok)
            last, i = tok, i + 1
            continue
        if tok not in s.single and tok not in s.repeated:
            return bad + [Violation("G12", _say(tok, known), i, "parsing stopped")]
        if i + 1 >= len(argv):
            return bad + [Violation("G13", tok, i)]
        val = argv[i + 1]
        if tok in s.single:
            if tok in seen:
                bad.append(Violation("G21", tok, i))
            seen.add(tok)
            if val != s.single[tok]:
                bad.append(Violation("G20", tok, i + 1))
        else:
            if val in seen_rep[tok]:
                bad.append(Violation("G21", tok, i + 1))
            seen_rep[tok].append(val)
        last, i = tok, i + 2
    bad += [Violation("G22", t) for t in sorted(s.single) if t not in seen]
    bad += [Violation("G22", t) for t in sorted(s.flags) if t not in seen_flags]
    for tok, want in sorted(s.repeated.items()):
        got = seen_rep[tok]
        if sorted(got) != sorted(want):
            extra = sum(1 for v in got if v not in want)
            missing = sum(1 for v in want if v not in got)
            bad.append(Violation("G23", tok, detail=f"{extra} unexpected, {missing} missing, {len(got)} given for "
                                                    f"{len(want)}"))
    if last != s.last_option:
        bad.append(Violation("G30", _say(s.last_option, known)))
    if argv[i:i + 1] != [s.image]:
        bad.append(Violation("G31", position=i))
    elif tuple(argv[i + 1:]) != s.payload:
        bad.append(Violation("G32", position=i + 1, detail=f"{len(argv) - i - 1} tokens given for {len(s.payload)}"))
    return bad
