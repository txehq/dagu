# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for argv_guard.py (TXE-8041). containerguard_test.go runs this file; directly:
    python3 -I -B test_argv_guard.py -v

No process, no network. Only FilesystemFloor touches files: its own fixtures (directories, regular files, symbolic
links, a FIFO), in a fresh directory it makes with tempfile.mkdtemp and removes; a link it makes is only lstat'd,
never followed, and no live path is read through it. The argv and schema below model a real run (TXE-8039's KG-r3
kubeguard run), written out here independently of any runner. Every credential-looking value is a FAKE sentinel.
"""
import dataclasses
import importlib.util
import inspect
import os
import random
import shutil
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("argv_guard", HERE / "argv_guard.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)

IMAGE = "sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea"
SCRATCH = "/s/runs"
W = "/s/runs/kg-1"
RUN = "run1-abcd1234"
NAME = "dagu8039-kg-" + RUN
LABELS = ("txe.owner=cc2-s8a81cd", "txe.ticket=TXE-8039", "txe.run=" + RUN)
ENVS = ("CGO_ENABLED=1", "GOFLAGS=-mod=readonly -buildvcs=false", "GOPROXY=file:///goproxy", "HOME=/w/home",
        "TMPDIR=/w/tmp")
SCRIPT = ("set -u; command -v python3 > /w/out/python.txt 2>&1 && python3 --version >> /w/out/python.txt 2>&1; "
          "go test -race -count=1 -v ./txe/kubeguard > /w/out/test.log 2>&1; exit 0")
PAYLOAD = ("-c", "timeout -k 20 900 /bin/sh -c '" + SCRIPT + "'")
SENT = "sekrit-7f3a91"          # a fake credential-shaped sentinel; it must never appear in a diagnostic


def mounts(w=W):
    return (f"type=bind,source={w}/src,target=/src,readonly", f"type=bind,source={w}/goproxy,target=/goproxy,readonly",
            f"type=bind,source={w}/w,target=/w")


def single(w=W):
    return {"--name": NAME, "--cidfile": f"{w}/cid", "--pull": "never", "--network": "none", "--cap-drop": "ALL",
            "--security-opt": "no-new-privileges", "--user": "501:20", "--cpus": "4", "--memory": "8g",
            "--memory-swap": "8g", "--pids-limit": "8192", "--ulimit": "nofile=65536:65536", "--stop-timeout": "10",
            "--hostname": "txe-gotest", "--workdir": "/src", "--entrypoint": "/bin/sh"}


def schema(**over):
    w = over.pop("w", W)
    s = G.Schema(image=IMAGE, work_dir=w, scratch=SCRATCH, flags=frozenset({"--read-only", "--init"}),
                 single=single(w), repeated={"--label": LABELS, "--env": ENVS, "--mount": mounts(w)},
                 last_option="--entrypoint", payload=PAYLOAD)
    return dataclasses.replace(s, **over)


def argv(w=W):
    a = ["create", "--name", NAME, "--cidfile", f"{w}/cid", "--pull", "never", "--network", "none", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges", "--read-only", "--init", "--user", "501:20", "--cpus", "4",
         "--memory", "8g", "--memory-swap", "8g", "--pids-limit", "8192", "--ulimit", "nofile=65536:65536",
         "--stop-timeout", "10", "--hostname", "txe-gotest", "--workdir", "/src"]
    for x in LABELS:
        a += ["--label", x]
    for x in ENVS:
        a += ["--env", x]
    for x in mounts(w):
        a += ["--mount", x]
    return a + ["--entrypoint", "/bin/sh", IMAGE, *PAYLOAD]


def codes(vs):
    return [v.code for v in vs]


def ins(*toks):
    def m(a):
        j = a.index("--entrypoint")
        a[j:j] = list(toks)
    return m


def setv(opt, val):
    def m(a):
        a[a.index(opt) + 1] = val
    return m


def drop(opt, n=2):
    def m(a):
        j = a.index(opt)
        del a[j:j + n]
    return m


def replace(old, new):
    def m(a):
        a[a.index(old)] = new
    return m


def network_eq(a):
    j = a.index("--network")
    a[j:j + 2] = ["--network=host"]


def entrypoint_not_last(a):
    j = a.index("--hostname")
    pair = a[j:j + 2]
    del a[j:j + 2]
    k = a.index(IMAGE)
    a[k:k] = pair


def no_goproxy(a):
    j = a.index(mounts()[1])
    del a[j - 1:j + 1]


# TXE-8039 KG-r3's 38 inert argv negatives, each with the code that must refuse it.
KG_NEGATIVES = [
    ("-v", ins("-v", "/Users/x:/host"), "G10"), ("--volume", ins("--volume", "/:/host"), "G10"),
    ("--volume=", ins("--volume=/:/host"), "G10"), ("-v=", ins("-v=/:/h"), "G10"), ("-e", ins("-e", "X=1"), "G10"),
    ("mount-home", ins("--mount", "type=bind,source=/Users/x,target=/h"), "G23"),
    ("mount-sock", ins("--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock"), "G23"),
    ("writable-src", replace(mounts()[0], f"type=bind,source={W}/src,target=/src"), "G23"),
    ("no-goproxy-mount", no_goproxy, "G23"),
    ("network-host", setv("--network", "host"), "G20"), ("network=host", network_eq, "G11"),
    ("no-network", drop("--network"), "G22"), ("network-twice", ins("--network", "none"), "G21"),
    ("privileged", ins("--privileged"), "G10"), ("cap-add", ins("--cap-add", "SYS_ADMIN"), "G10"),
    ("seccomp", setv("--security-opt", "seccomp=unconfined"), "G20"), ("pid", ins("--pid", "host"), "G10"),
    ("ipc", ins("--ipc", "host"), "G10"), ("userns", ins("--userns", "host"), "G10"),
    ("env-file", ins("--env-file", "/x"), "G10"), ("device", ins("--device", "/dev/kvm"), "G10"),
    ("publish", ins("-p", "8080:80"), "G10"), ("env-token", ins("--env", "GH_TOKEN=x"), "G23"),
    ("env-changed", replace("GOPROXY=file:///goproxy", "GOPROXY=https://proxy.golang.org"), "G23"),
    ("label-changed", replace("txe.ticket=TXE-8039", "txe.ticket=TXE-7976"), "G23"),
    ("pull-always", setv("--pull", "always"), "G20"), ("no-read-only", drop("--read-only", 1), "G22"),
    ("no-cidfile", drop("--cidfile"), "G22"), ("cidfile-elsewhere", setv("--cidfile", "/tmp/cid"), "G20"),
    ("user-root", setv("--user", "0:0"), "G20"), ("cpus-12", setv("--cpus", "12"), "G20"),
    ("tmpfs", ins("--tmpfs", "/tmp:rw"), "G12"), ("unknown-option", ins("--log-driver", "none"), "G12"),
    ("entrypoint-bash", setv("--entrypoint", "/bin/bash"), "G20"),
    ("entrypoint-not-last", entrypoint_not_last, "G30"), ("image", replace(IMAGE, "golang:latest"), "G31"),
    ("payload", lambda a: a.__setitem__(-1, a[-1].replace("go test", "go test -x")), "G32"),
    ("extra-arg", lambda a: a.append("x"), "G32"),
]

# runner-final's joined-substring list (txe-evidence runner-final.py c7c97084, argv_violations), and the rule here
# that refuses each as a real Docker argv or schema.
# docker/cli v29.7.1's own arity for each allowed option, written out here from the source (cli/command/container/
# opts.go addFlags and create.go; TXE-8041 evidence ARITY-v29.7.1.md cites file and line): BoolVar is "flag";
# StringVar/IntVar/Int64Var and the single-value Var types MemBytes, MemSwapBytes, NanoCPUs are "single"; the
# accumulating Var types ListOpts, MountOpt, NetworkOpt, UlimitOpt are "list".
CITED_ARITY = {
    "--read-only": "flag", "--init": "flag", "--rm": "flag",
    "--name": "single", "--pull": "single", "--cidfile": "single", "--user": "single", "--cpus": "single",
    "--memory": "single", "--memory-swap": "single", "--pids-limit": "single", "--stop-timeout": "single",
    "--hostname": "single", "--workdir": "single", "--entrypoint": "single", "--log-driver": "single",
    "--network": "list", "--cap-drop": "list", "--security-opt": "list", "--ulimit": "list", "--label": "list",
    "--env": "list", "--mount": "list", "--tmpfs": "list",
}

OLD_SUBSTRINGS = {
    "--privileged": "G10", "docker.sock": "S08", "/var/run": "S08", "--cap-add": "G10", "--network host": "G20",
    "--network=host": "G11", "--env-file": "G10", "--pid host": "G10", "--ipc host": "G10", "--userns host": "G10",
    "-v ": "G10", "--volume": "G10", "/Users/cwang:": "G10", "source=/Users/cwang,": "S06", "GH_TOKEN": "S11",
    "SSH_AUTH_SOCK": "S11", "--pull always": "G20", "seccomp=unconfined": "G20",
}


class Positive(unittest.TestCase):
    def test_the_reviewed_argv_is_clean_and_its_payload_holds_v_flags(self):
        self.assertEqual(G.check_schema(schema()), [])
        self.assertEqual(G.violations(argv(), schema()), [])
        self.assertIn("command -v python3", PAYLOAD[1])
        self.assertIn("go test -race -count=1 -v ./txe/kubeguard", PAYLOAD[1])

    def test_the_payload_is_compared_whole(self):
        self.assertEqual(codes(G.violations(argv(), schema(payload=("-c", "true")))), ["G32"])


class KGNegatives(unittest.TestCase):
    def test_every_kg_r3_negative_is_refused_with_its_code(self):
        self.assertEqual(len(KG_NEGATIVES), 38)
        for label, mut, code in KG_NEGATIVES:
            with self.subTest(label):
                a = argv()
                mut(a)
                got = codes(G.violations(a, schema()))
                self.assertIn(code, got, (label, got))

    def test_a_work_dir_outside_scratch_is_refused(self):
        self.assertIn("S01", codes(G.violations(argv("/tmp/W"), schema(w="/tmp/W"))))

    def test_every_old_substring_maps_to_a_rule_that_fires(self):
        self.assertEqual(len(OLD_SUBSTRINGS), 18)
        cases = {
            "--privileged": argv_with(ins("--privileged")), "--cap-add": argv_with(ins("--cap-add", "X")),
            "--network host": argv_with(setv("--network", "host")), "--network=host": argv_with(network_eq),
            "--env-file": argv_with(ins("--env-file", "/x")), "--pid host": argv_with(ins("--pid", "host")),
            "--ipc host": argv_with(ins("--ipc", "host")), "--userns host": argv_with(ins("--userns", "host")),
            "-v ": argv_with(ins("-v", "/a:/b")), "--volume": argv_with(ins("--volume", "/a:/b")),
            "/Users/cwang:": argv_with(ins("-v", "/Users/cwang:/h")),
            "--pull always": argv_with(setv("--pull", "always")),
            "seccomp=unconfined": argv_with(setv("--security-opt", "seccomp=unconfined")),
        }
        for sub, a in cases.items():
            with self.subTest(sub):
                self.assertIn(OLD_SUBSTRINGS[sub], codes(G.violations(a, schema())))
        schemas = {
            "docker.sock": schema_mount(f"type=bind,source={W}/docker.sock,target=/sock,readonly"),
            "/var/run": schema_mount("type=bind,source=/var/run/x,target=/x,readonly"),
            "source=/Users/cwang,": schema_mount("type=bind,source=/Users/cwang,target=/h,readonly"),
            "GH_TOKEN": schema_env("GH_TOKEN=x"), "SSH_AUTH_SOCK": schema_env("SSH_AUTH_SOCK=/x"),
        }
        for sub, s in schemas.items():
            with self.subTest(sub):
                self.assertIn(OLD_SUBSTRINGS[sub], codes(G.check_schema(s)))
        self.assertEqual(set(cases) | set(schemas), set(OLD_SUBSTRINGS))


def argv_with(mut):
    a = argv()
    mut(a)
    return a


def schema_mount(extra):
    s = schema()
    return dataclasses.replace(s, repeated={**s.repeated, "--mount": s.repeated["--mount"] + (extra,)})


def schema_env(extra):
    s = schema()
    return dataclasses.replace(s, repeated={**s.repeated, "--env": s.repeated["--env"] + (extra,)})


def schema_single(**kv):
    s = schema()
    d = dict(s.single)
    for k, v in kv.items():
        if v is None:
            d.pop(k, None)
        else:
            d[k] = v
    return dataclasses.replace(s, single=d)


class PolicyFloor(unittest.TestCase):
    """A consumer schema that tries to loosen the floor is refused, structurally."""

    def test_each_loosened_schema_is_refused(self):
        s0 = schema()
        cases = [
            ("network-host", schema_single(**{"--network": "host"}), "S02"),
            ("pull-always", schema_single(**{"--pull": "always"}), "S02"),
            ("no-cap-drop", schema_single(**{"--cap-drop": None}), "S02"),
            ("security-opt", schema_single(**{"--security-opt": "seccomp=unconfined"}), "S02"),
            ("no-read-only", dataclasses.replace(s0, flags=frozenset({"--init"})), "S03"),
            ("denied-in-schema", schema_single(**{"--privileged": "x"}), "S04"),
            ("two-kinds", schema_single(**{"--init": "x"}), "S04"),
            ("eq-key", schema_single(**{"--network=host": "x"}), "S04"),
            ("user-root", schema_single(**{"--user": "0:0"}), "S13"),
            ("user-name-root", schema_single(**{"--user": "root"}), "S13"),
            ("user-absent", schema_single(**{"--user": None}), "S13"),
            ("image-tag", dataclasses.replace(s0, image="golang:1.27"), "S14"),
            ("payload-empty", dataclasses.replace(s0, payload=()), "S15"),
            ("payload-list", dataclasses.replace(s0, payload=["-c", "x"]), "S15"),
            ("mount-alias", schema_mount(f"type=bind,src={W}/a,target=/a,readonly"), "S05"),
            ("mount-volume", schema_mount(f"type=volume,source={W}/a,target=/a,readonly"), "S05"),
            ("mount-dup-key", schema_mount(f"type=bind,source={W}/a,source={W}/b,target=/a,readonly"), "S05"),
            ("mount-ro-early", schema_mount(f"type=bind,readonly,source={W}/a,target=/a"), "S05"),
            ("mount-outside", schema_mount("type=bind,source=/home/x,target=/a,readonly"), "S06"),
            ("mount-dotdot", schema_mount(f"type=bind,source={W}/../../../etc,target=/a,readonly"), "S06"),
            ("mount-is-workdir", schema_mount(f"type=bind,source={W},target=/a,readonly"), "S06"),
            ("target-root", schema_mount(f"type=bind,source={W}/a,target=/,readonly"), "S07"),
            ("target-proc", schema_mount(f"type=bind,source={W}/a,target=/proc/1,readonly"), "S07"),
            ("target-relative", schema_mount(f"type=bind,source={W}/a,target=a,readonly"), "S07"),
            ("socket-source", schema_mount(f"type=bind,source={W}/docker.sock,target=/s,readonly"), "S08"),
            ("socket-target", schema_mount(f"type=bind,source={W}/a,target=/x/docker.sock,readonly"), "S08"),
            ("writable-undeclared", schema_mount(f"type=bind,source={W}/a,target=/a"), "S09"),
            ("dup-target", schema_mount(f"type=bind,source={W}/a,target=/src,readonly"), "S10"),
            ("env-token", schema_env("GH_TOKEN=x"), "S11"),
            ("env-agent", schema_env("SSH_AUTH_SOCK=/x"), "S11"),
            ("env-aws", schema_env("AWS_SECRET_ACCESS_KEY=x"), "S11"),
            ("env-lower", schema_env("home=/x"), "S11"),
            ("env-dup-key", schema_env("HOME=/other"), "S11"),
            ("label-bad", dataclasses.replace(s0, repeated={**s0.repeated, "--label": LABELS + ("Bad Key=x",)}),
             "S12"),
            ("label-dup", dataclasses.replace(s0, repeated={**s0.repeated, "--label": LABELS + ("txe.run=x",)}),
             "S12"),
            ("tmpfs-proc", dataclasses.replace(s0, repeated={**s0.repeated, "--tmpfs": ("/proc:rw",)}), "S16"),
            ("workdir-outside", schema(w="/tmp/W"), "S01"),
            ("workdir-is-scratch", dataclasses.replace(s0, work_dir=SCRATCH), "S01"),
            ("workdir-dotdot", dataclasses.replace(s0, work_dir=SCRATCH + "/a/.."), "S01"),
            ("scratch-relative", dataclasses.replace(s0, scratch="s/runs"), "S01"),
            ("repeated-dup", dataclasses.replace(s0, repeated={**s0.repeated, "--env": ENVS + (ENVS[0],)}), "S04"),
            ("not-a-schema", {"image": IMAGE}, "S17"),
            ("single-not-dict", dataclasses.replace(s0, single=[("--name", NAME)]), "S17"),
        ]
        for label, s, code in cases:
            with self.subTest(label):
                got = codes(G.check_schema(s))
                self.assertIn(code, got, (label, got))
                self.assertNotEqual(G.violations(argv(), s), [], label)

    def test_the_user_must_be_a_canonical_nonzero_numeric_id(self):
        """PR 299 review of 32dc13f1: `--user 00:0` passed, and Docker reads "00" with strconv.Atoi as uid 0 (root).
        The user is exactly uid:gid, both canonical nonzero decimals. A bare uid is refused (root's r14 correction)."""
        refused = ("00:0", "", ":", "00", "+0", "-0", "0000", "007", "root", "toor", " 1000", "1000 ", "1000:",
                   "1000:0", "1000:+0", "1000:01", "1000:1000:1000", "0:1000",
                   "1", "1000")    # a bare uid: no unspecified-gid exception, the image's default group is refused
        self.assertEqual(len(refused), 20)
        for user in refused:
            with self.subTest(user):
                self.assertIn("S13", codes(G.check_schema(schema_single(**{"--user": user}))), user)
        for user in ("1000:1000", "501:20"):
            with self.subTest(user):
                self.assertEqual(G.check_schema(schema_single(**{"--user": user})), [], user)

    def test_a_policy_option_in_the_wrong_kind_is_refused(self):
        """PR 299 review (P2): a --mount in `single` skipped every mount rule. Each policy option has one kind."""
        s0 = schema()

        def moved(opt, to, value):
            rep = {k: v for k, v in s0.repeated.items() if k != opt}
            single = {k: v for k, v in s0.single.items() if k != opt}
            flags = set(s0.flags) - {opt}
            if to == "single":
                single[opt] = value
            elif to == "repeated":
                rep[opt] = (value,)
            else:
                flags.add(opt)
            return dataclasses.replace(s0, single=single, repeated=rep, flags=frozenset(flags))
        cases = [
            ("mount-in-single", moved("--mount", "single", "type=bind,source=/,target=/host")),
            ("env-in-single", moved("--env", "single", "GH_TOKEN=x")),
            ("label-in-single", moved("--label", "single", "txe.run=x")),
            ("tmpfs-in-single", moved("--tmpfs", "single", "/proc:rw")),
            ("mount-in-flags", moved("--mount", "flags", None)),
            ("user-in-repeated", moved("--user", "repeated", "0:0")),
            ("network-in-repeated", moved("--network", "repeated", "host")),
            ("read-only-in-single", moved("--read-only", "single", "true")),
        ]
        for label, s in cases:
            with self.subTest(label):
                self.assertIn("S04", codes(G.check_schema(s)), label)

    def test_the_review_repro_mount_in_single_is_refused_by_schema_and_argv(self):
        s0 = schema()
        s = dataclasses.replace(s0, repeated={k: v for k, v in s0.repeated.items() if k != "--mount"},
                                single={**s0.single, "--mount": "type=bind,source=/,target=/host"})
        a = [x for x in argv() if not x.startswith("type=bind,")]
        a = [x for i, x in enumerate(a) if not (x == "--mount")]
        j = a.index("--entrypoint")
        a[j:j] = ["--mount", "type=bind,source=/,target=/host"]
        self.assertIn("S04", codes(G.check_schema(s)))
        self.assertNotEqual(G.violations(a, s), [])

    def test_the_security_review_repros_arity_and_alias_are_refused(self):
        """PR 299 security review: a docker boolean declared as single-valued (`--init` taking "--privileged"), and a
        short alias beside its long form (`-u 0` beside `--user 501:20`), each passed the floor."""
        s0 = schema()
        arity = dataclasses.replace(s0, flags=frozenset({"--read-only"}), single={**s0.single, "--init": "--privileged"})
        got = codes(G.check_schema(arity))
        self.assertIn("S04", got)
        self.assertIn("S18", got)
        a = argv()
        j = a.index("--init")
        a[j:j + 1] = ["--init", "--privileged"]
        self.assertNotEqual(G.violations(a, arity), [])
        alias = dataclasses.replace(s0, single={**s0.single, "-u": "0"})
        self.assertIn("S04", codes(G.check_schema(alias)))
        b = argv()
        k = b.index("--entrypoint")
        b[k:k] = ["-u", "0"]
        self.assertNotEqual(G.violations(b, alias), [])

    def test_every_option_must_be_listed_canonical_and_match_its_arity(self):
        """Each option in every schema kind its docker arity forbids, the short-alias class, and an unlisted option."""
        self.assertEqual(G.CREATE_OPTIONS, CITED_ARITY)
        s0 = schema()

        def only_in(opt, kind):
            flags = set(s0.flags) - {opt}
            single = {k: v for k, v in s0.single.items() if k != opt}
            rep = {k: v for k, v in s0.repeated.items() if k != opt}
            if kind == "flags":
                flags.add(opt)
            elif kind == "single":
                single[opt] = "x"
            else:
                rep[opt] = ("x",)
            return dataclasses.replace(s0, flags=frozenset(flags), single=single, repeated=rep)
        allowed = {"flag": {"flags"}, "single": {"single"}, "list": {"single", "repeated"}}
        cases = [(f"{ar} {opt} as {kind}", only_in(opt, kind))
                 for opt, ar in sorted(CITED_ARITY.items())
                 for kind in ("flags", "single", "repeated") if kind not in allowed[ar]]
        self.assertEqual(len(cases), 3 * 2 + 13 * 2 + 8 * 1)
        for alias in ("-u", "-w", "-l", "-m", "-h", "-e", "-v", "-p", "-c", "-i", "-t", "-d"):
            cases.append((f"alias {alias}", dataclasses.replace(s0, single={**s0.single, alias: "x"})))
        cases.append(("unlisted --log-opt", dataclasses.replace(s0, single={**s0.single, "--log-opt": "x"})))
        for label, s in cases:
            with self.subTest(label):
                self.assertIn("S04", codes(G.check_schema(s)), label)

    def test_duplicate_and_conflicting_options_are_refused(self):
        """The 'once' rule and its conflicts: a single option or a flag given twice, a value option repeated where
        only one is allowed, a short alias beside its long form, an option in two schema kinds."""
        s0 = schema()
        cases = [
            ("hostname-twice", ins("--hostname", "txe-gotest"), "G21"),
            ("user-twice-different", ins("--user", "0:0"), "G21"),
            ("read-only-twice", ins("--read-only"), "G21"),
            ("init-twice", ins("--init"), "G21"),
            ("alias-beside-long", ins("-u", "0"), "G12"),
        ]
        for label, mut, code in cases:
            with self.subTest(label):
                a = argv()
                mut(a)
                self.assertIn(code, codes(G.violations(a, s0)), label)
        with self.subTest("single-option-in-single-and-repeated"):
            both = dataclasses.replace(s0, repeated={**s0.repeated, "--hostname": ("txe-gotest",)})
            self.assertIn("S04", codes(G.check_schema(both)))

    def test_a_dash_leading_value_is_refused(self):
        s0 = schema()
        for label, s in (("single", schema_single(**{"--hostname": "--privileged"})),
                         ("repeated", dataclasses.replace(s0, repeated={**s0.repeated,
                                                                        "--label": LABELS + ("--privileged",)}))):
            with self.subTest(label):
                self.assertIn("S18", codes(G.check_schema(s)), label)

    def test_every_listed_option_in_its_kind_keeps_a_runner_shaped_schema_clean(self):
        """The allowlist holds the union of the launchers' options: a KG-shaped schema plus --rm, --log-driver and a
        --tmpfs (the mutate-style options) is still clean."""
        s0 = schema()
        s = dataclasses.replace(s0, flags=frozenset(s0.flags) | {"--rm"},
                                single={**s0.single, "--log-driver": "none"},
                                repeated={**s0.repeated, "--tmpfs": ("/tmp:rw,nosuid,nodev,size=1g",)})
        self.assertEqual(G.check_schema(s), [])
        used = set(s.flags) | set(s.single) | set(s.repeated)
        self.assertEqual(used, set(G.CREATE_OPTIONS))
        # a list option is allowed in either kind its arity permits: --ulimit as repeated is clean too
        s2 = dataclasses.replace(s, single={k: v for k, v in s.single.items() if k != "--ulimit"},
                                 repeated={**s.repeated, "--ulimit": ("nofile=65536:65536",)})
        self.assertEqual(G.check_schema(s2), [])

    def test_a_double_leading_slash_is_refused_in_every_path_input(self):
        """PR 299 review (P2): posixpath.normpath keeps a leading "//", which Linux resolves as "/", so a mount onto
        //proc passed both validators. Each path policy input, and each alias of an allowed path, is refused."""
        s0 = schema()
        ro = ",readonly"
        cases = [
            ("mount-target-//proc", schema_mount(f"type=bind,source={W}/a,target=//proc{ro}"), "S07"),
            ("mount-target-//", schema_mount(f"type=bind,source={W}/a,target=//{ro}"), "S07"),
            ("mount-target-///proc", schema_mount(f"type=bind,source={W}/a,target=///proc{ro}"), "S07"),
            ("mount-source-//", schema_mount(f"type=bind,source=/{W}/a,target=/a{ro}"), "S06"),
            ("tmpfs-//proc", dataclasses.replace(s0, repeated={**s0.repeated, "--tmpfs": ("//proc:rw",)}), "S16"),
            ("writable-target-//proc", dataclasses.replace(s0, writable_targets=frozenset({"/w", "//proc"})), "S19"),
            ("writable-target-system", dataclasses.replace(s0, writable_targets=frozenset({"/w", "/proc"})), "S19"),
            ("work-dir-//", dataclasses.replace(s0, work_dir="/" + W), "S01"),
            ("scratch-//", dataclasses.replace(s0, scratch="/" + SCRATCH), "S01"),
            # duplicate aliases: the second spelling of an allowed path is refused, never treated as another path
            ("target-/w-and-//w", schema_mount(f"type=bind,source={W}/b,target=//w"), "S07"),
            ("target-/src-and-//src", schema_mount(f"type=bind,source={W}/b,target=//src{ro}"), "S07"),
            ("writable-/w-and-//w", dataclasses.replace(s0, writable_targets=frozenset({"/w", "//w"})), "S19"),
        ]
        for label, s, code in cases:
            with self.subTest(label):
                self.assertIn(code, codes(G.check_schema(s)), label)
        for p in ("/", "/w", "/s/runs/kg-1/src"):
            self.assertTrue(G._normal_abs(p), p)
        for p in ("//", "//proc", "///proc", "/a//b", "/a/", "/./a", "/a/../b", "a", "", "/a\x00"):
            self.assertFalse(G._normal_abs(p), p)

    def test_a_writable_mount_is_allowed_only_at_a_declared_target(self):
        s = schema_mount(f"type=bind,source={W}/cache,target=/cache")
        self.assertIn("S09", codes(G.check_schema(s)))
        s2 = dataclasses.replace(s, writable_targets=frozenset({"/w", "/cache"}))
        self.assertEqual(G.check_schema(s2), [])


class Redaction(unittest.TestCase):
    """No diagnostic carries a value or an unknown token, from the argv or the schema."""

    def leaks(self, vs):
        text = str(vs) + repr(vs) + "".join(str(v) + repr(v) for v in vs)
        return SENT.lower() in text.lower() or "7f3a91" in text

    def test_sentinels_in_the_argv_never_reach_a_diagnostic(self):
        cases = [
            ins("--env", f"AWS_X={SENT}"), ins(f"--{SENT}"), ins(f"--x={SENT}"), ins("-\x00" + SENT),
            ins(f"--volume={SENT}"), ins(f"-v={SENT}"), ins("--mount", f"type=bind,source=/{SENT},target=/x"),
            setv("--hostname", SENT), setv("--name", SENT), replace("txe.ticket=TXE-8039", f"txe.ticket={SENT}"),
            replace(IMAGE, SENT), lambda a: a.__setitem__(-1, SENT), lambda a: a.append(SENT),
            lambda a: a.insert(1, f"--{SENT}=1"), lambda a: a.insert(1, SENT * 3),
        ]
        for i, mut in enumerate(cases):
            with self.subTest(i):
                a = argv()
                mut(a)
                vs = G.violations(a, schema())
                self.assertNotEqual(vs, [])
                self.assertFalse(self.leaks(vs), [str(v) for v in vs])
                self.assertTrue(all(v.code in G.CODES for v in vs))

    def test_sentinels_in_a_schema_never_reach_a_diagnostic(self):
        s0 = schema()
        cases = [
            schema_env(f"X_{SENT.upper().replace('-', '_')}_TOKEN=1"), schema_env(f"OK={SENT}"),
            schema_mount(f"type=bind,source=/{SENT},target=/x,readonly"),
            schema_single(**{"--network": SENT}), dataclasses.replace(s0, image=SENT),
            dataclasses.replace(s0, work_dir="/" + SENT),
        ]
        for i, s in enumerate(cases):
            with self.subTest(i):
                vs = G.check_schema(s) + G.violations(argv(), s)
                self.assertNotEqual(vs, [])
                self.assertFalse(self.leaks(vs), [str(v) for v in vs])

    def test_sentinel_keys_in_every_schema_kind_never_reach_a_diagnostic(self):
        """PR 299 review of cdb78d1d: a schema KEY reached a runtime diagnostic (`G22 --x=sekrit-7f3a91`). A sentinel
        key in flags, single and repeated, through check_schema, violations (with the reviewed argv and with the key
        inserted into it) and check_mount_sources: in no field of any Violation, nor in its str or repr."""
        s0 = schema()
        for key in (f"--x={SENT}", f"--{SENT}", SENT):
            for kind in ("flags", "single", "repeated"):
                with self.subTest(f"{kind}:{key}"):
                    if kind == "flags":
                        s = dataclasses.replace(s0, flags=s0.flags | {key})
                    elif kind == "single":
                        s = dataclasses.replace(s0, single={**s0.single, key: "x"})
                    else:
                        s = dataclasses.replace(s0, repeated={**s0.repeated, key: ("x",)})
                    with_key = argv()
                    ins(key, "x")(with_key)
                    vs = G.check_schema(s) + G.violations(argv(), s) + G.violations(with_key, s) + \
                        G.check_mount_sources(s)
                    self.assertIn("S04", codes(vs))
                    self.assertFalse(self.leaks(vs), [str(v) for v in vs])
                    for v in vs:
                        self.assertFalse(any(SENT in str(x) for x in dataclasses.astuple(v)), v)

    def test_the_review_repro_reports_the_schema_and_parses_nothing(self):
        """The reviewer's exact repro: single['--x=sekrit-7f3a91'] = 'x'. violations returns check_schema's findings
        and nothing from parsing the argv (no G code): an invalid schema has nothing to compare against."""
        s = schema_single(**{f"--x={SENT}": "x"})
        vs = G.violations(argv(), s)
        self.assertEqual(vs, G.check_schema(s))
        self.assertEqual(codes(vs), ["S04"])
        self.assertEqual(vs[0].option, G.UNRECOGNISED)
        self.assertFalse(self.leaks(vs))
        self.assertEqual(G.violations(["create", "--privileged", SENT], s), G.check_schema(s))

    def test_a_violation_stores_only_constants_whatever_it_is_given(self):
        """Redaction is the Violation type's invariant (a direct construction), so no call site can leak."""
        v = G.Violation("G22", f"--x={SENT}", 3, f"{SENT} given")
        self.assertEqual((v.option, v.position, v.detail), (G.UNRECOGNISED, 3, G.REDACTED))
        self.assertFalse(self.leaks([v]))
        cases = [
            ("option-not-str", G.Violation("G22", 5).option, G.UNRECOGNISED),
            ("option-sentinel-alone", G.Violation("G22", SENT).option, G.UNRECOGNISED),
            ("option-constant-kept", G.Violation("G22", "--network").option, "--network"),
            ("option-denied-kept", G.Violation("G10", "-v").option, "-v"),
            ("detail-not-str", G.Violation("G23", detail=7).detail, G.REDACTED),
            ("detail-count-kept", G.Violation("G23", detail="1 unexpected, 0 missing, 4 given for 3").detail,
             "1 unexpected, 0 missing, 4 given for 3"),
            ("detail-count-with-text", G.Violation("G32", detail=f"2 tokens given for 1 {SENT}").detail, G.REDACTED),
            ("detail-phrase-kept", G.Violation("G10", detail="parsing stopped").detail, "parsing stopped"),
            ("position-not-int", G.Violation("G20", position="7").position, -1),
            ("position-bool", G.Violation("G20", position=True).position, -1),
        ]
        for label, got, want in cases:
            with self.subTest(label):
                self.assertEqual(got, want)
        with self.subTest("unknown-code"):
            with self.assertRaises(ValueError):
                G.Violation(SENT)
        with self.subTest("fields"):      # a new field must be added here, and redacted, deliberately
            self.assertEqual([f.name for f in dataclasses.fields(G.Violation)], ["code", "option", "position",
                                                                                  "detail"])

    def test_random_sentinel_keys_never_echo(self):
        rng = random.Random(80411)
        keys = [f"--x={SENT}", f"--{SENT}", SENT, f"-{SENT}", f"--network={SENT}", f"--mount{SENT}", "--" + SENT * 2]
        s0 = schema()
        for _ in range(300):
            flags, single, repeated = set(s0.flags), dict(s0.single), dict(s0.repeated)
            for _ in range(rng.randint(1, 3)):
                key = rng.choice(keys)
                kind = rng.choice(("flags", "single", "repeated"))
                if kind == "flags":
                    flags.add(key)
                elif kind == "single":
                    single[key] = rng.choice(("x", SENT, "-x"))
                else:
                    repeated[key] = (rng.choice(("x", SENT)),)
            s = dataclasses.replace(s0, flags=frozenset(flags), single=single, repeated=repeated)
            a = argv()
            if rng.random() < 0.5:
                ins(rng.choice(keys), SENT)(a)
            vs = G.check_schema(s) + G.violations(a, s) + G.check_mount_sources(s)
            self.assertNotEqual(vs, [])
            self.assertFalse(self.leaks(vs), [str(v) for v in vs])
            self.assertTrue(all(v.code in G.CODES for v in vs))

    def test_malformed_argv_never_raises_and_never_echoes(self):
        for a in (None, [], ["run"], "create --x", [b"create"], ["create", 1, SENT], ["create", None],
                  ["create", "--name"], ["create", "--" + SENT]):
            with self.subTest(repr(type(a))):
                vs = G.violations(a, schema())
                self.assertNotEqual(vs, [])
                self.assertFalse(self.leaks(vs))

    def test_random_argv_never_raises_and_never_echoes(self):
        rng = random.Random(8041)
        pool = argv() + [SENT, f"--{SENT}", f"--x={SENT}", "-v", "--mount", "=", "-", "--", "\x00", "create", IMAGE]
        for _ in range(500):
            a = ["create"] + [rng.choice(pool) for _ in range(rng.randint(0, 60))]
            vs = G.violations(a, schema())
            self.assertFalse(self.leaks(vs), a)
            self.assertTrue(all(v.code in G.CODES for v in vs))


class FilesystemFloor(unittest.TestCase):
    """check_mount_sources (PR 299 security review of cdb78d1d: a bind source linked to the Docker socket passed the
    string floor). Each fixture is built in its own fresh directory from tempfile.mkdtemp, removed afterwards; its
    schema passes check_schema, so only the filesystem differs. Every path a fixture makes, and every link TARGET it
    names, is under that root: no live resource is named. A link is only lstat'd, never followed."""

    def fresh(self):
        root = os.path.realpath(tempfile.mkdtemp(prefix="cg-fs-"))     # realpath: the tmp dir's own ancestors
        self.assertFalse(os.path.islink(root))       # rmtree also refuses a link root rather than following it
        self.addCleanup(shutil.rmtree, root)
        work = root + "/s/w"
        for d in ("src", "goproxy", "w"):
            os.makedirs(f"{work}/{d}")
        return root, work

    def floor(self, work, extra=(), cidfile=None):
        s = schema(w=work)
        single = s.single if cidfile is None else {**s.single, "--cidfile": cidfile}
        s = dataclasses.replace(s, scratch=work.rsplit("/", 1)[0], single=single,
                                repeated={**s.repeated, "--mount": s.repeated["--mount"] + tuple(extra)})
        self.assertEqual(G.check_schema(s), [])
        return G.check_mount_sources(s)

    @staticmethod
    def file(path):
        with open(path, "w") as f:
            f.write("x")

    def test_each_fixture_gets_its_code(self):
        ro = "type=bind,source={},target=/extra,readonly"

        def plain(root, w):
            return w, ()

        def file_source(root, w):
            os.rmdir(f"{w}/src")
            self.file(f"{w}/src")
            return w, ()

        def review_repro(root, w):           # the reviewer's shape, aimed at an OWNED name: ANY link refuses unfollowed
            os.symlink(f"{root}/sock-target", f"{w}/innocent")
            return w, (ro.format(f"{w}/innocent"),)

        def leaf_link(root, w):
            os.rmdir(f"{w}/src")
            os.mkdir(f"{root}/elsewhere")
            os.symlink(f"{root}/elsewhere", f"{w}/src")
            return w, ()

        def intermediate_link(root, w):
            os.makedirs(f"{root}/real-d/in")
            os.symlink(f"{root}/real-d", f"{w}/d")
            return w, (ro.format(f"{w}/d/in"),)

        def dangling_link(root, w):
            os.rmdir(f"{w}/src")
            os.symlink(f"{root}/nowhere", f"{w}/src")
            return w, ()

        def readonly_fifo(root, w):
            os.rmdir(f"{w}/goproxy")
            os.mkfifo(f"{w}/goproxy")
            return w, ()

        def writable_fifo(root, w):
            os.rmdir(f"{w}/w")
            os.mkfifo(f"{w}/w")
            return w, ()

        def missing_source(root, w):
            os.rmdir(f"{w}/src")
            return w, ()

        def file_as_directory(root, w):        # an inspection error: ENOTDIR
            self.file(f"{w}/f")
            return w, (ro.format(f"{w}/f/x"),)

        def name_too_long(root, w):            # an inspection error: ENAMETOOLONG
            return w, (ro.format(f"{w}/" + "n" * 300),)

        def work_dir_link(root, w):
            os.rename(w, f"{root}/s/real-w")
            os.symlink(f"{root}/s/real-w", f"{root}/s/lw")
            return f"{root}/s/lw", ()

        def ancestor_link(root, w):
            os.rename(f"{root}/s", f"{root}/real")
            os.symlink(f"{root}/real", f"{root}/a")
            return f"{root}/a/w", ()

        def work_dir_missing(root, w):
            return f"{root}/s/none", ()

        def work_dir_a_file(root, w):
            self.file(f"{root}/s/wf")
            return f"{root}/s/wf", ()

        cases = [
            ("clean", plain, []), ("regular-file-source", file_source, []),
            ("review-repro-link", review_repro, ["F01"]), ("leaf-link", leaf_link, ["F01"]),
            ("intermediate-link", intermediate_link, ["F01"]), ("dangling-link", dangling_link, ["F01"]),
            ("readonly-source-fifo", readonly_fifo, ["F02"]), ("writable-source-fifo", writable_fifo, ["F02"]),
            ("missing-source", missing_source, ["F03"]), ("file-as-directory", file_as_directory, ["F03"]),
            ("name-too-long", name_too_long, ["F03"]),
            # the work dir's own finding, then the cidfile's ({work}/cid: its parent IS the work dir), then each source
            ("work-dir-link", work_dir_link, ["F01"] * 5), ("ancestor-link", ancestor_link, ["F01"] * 5),
            ("work-dir-missing", work_dir_missing, ["F03"] * 5),
            ("work-dir-a-file", work_dir_a_file, ["F02", "F02", "F03", "F03", "F03"]),
        ]
        self.assertEqual(len(cases), 15)
        for label, make, want in cases:
            with self.subTest(label):
                root, w = self.fresh()
                work, extra = make(root, w)
                vs = self.floor(work, extra)
                self.assertEqual(codes(vs), want, label)
                self.assertFalse(any(root in str(v) or root in repr(v) for v in vs), label)    # no path is echoed
                work_level = len(want) == 5
                if work_level:
                    self.assertEqual((vs[0].option, vs[0].detail), ("", "the work dir"), label)
                    self.assertEqual(vs[1].option, "--cidfile", label)
                self.assertTrue(all(v.option == "--mount" for v in vs[2 if work_level else 0:]), label)

    def test_the_cidfile_preflight(self):
        """Root's ruling on PR 299 (the --cidfile is the same host-path class): the parent chain from "/" has no link,
        is present and readable and ends in a directory, and the leaf is ABSENT. An existing leaf, a dangling link
        included, refuses without being followed. Docker's O_EXCL create stays a second check at create time."""
        def absent(root, w):
            return f"{w}/cid"

        def linked_parent(root, w):
            os.mkdir(f"{root}/real-p")
            os.symlink(f"{root}/real-p", f"{root}/lp")
            return f"{root}/lp/cid"

        def existing_regular(root, w):
            self.file(f"{w}/cid")
            return f"{w}/cid"

        def existing_directory(root, w):
            os.mkdir(f"{w}/cid")
            return f"{w}/cid"

        def dangling_leaf(root, w):
            os.symlink(f"{root}/nowhere", f"{w}/cid")
            return f"{w}/cid"

        def leaf_link_to_owned_file(root, w):
            self.file(f"{root}/target")
            os.symlink(f"{root}/target", f"{w}/cid")
            return f"{w}/cid"

        def non_directory_parent(root, w):
            self.file(f"{w}/f")
            return f"{w}/f/cid"

        def missing_parent(root, w):
            return f"{w}/none/cid"

        def parent_name_too_long(root, w):     # an inspection error in the parent chain: ENAMETOOLONG
            return f"{w}/" + "n" * 300 + "/cid"

        def leaf_name_too_long(root, w):       # an inspection error on the leaf itself: ENAMETOOLONG, not ENOENT
            return f"{w}/" + "n" * 300

        def relative(root, w):
            return "cid"

        def dot_dot(root, w):
            return f"{w}/../cid"

        cases = [
            ("clean-absent-leaf", absent, []), ("linked-parent", linked_parent, ["F01"]),
            ("existing-regular-leaf", existing_regular, ["F04"]),
            ("existing-directory-leaf", existing_directory, ["F04"]),
            ("dangling-leaf", dangling_leaf, ["F04"]), ("leaf-link-to-owned-file", leaf_link_to_owned_file, ["F04"]),
            ("non-directory-parent", non_directory_parent, ["F02"]), ("missing-parent", missing_parent, ["F03"]),
            ("parent-name-too-long", parent_name_too_long, ["F03"]),
            ("leaf-name-too-long", leaf_name_too_long, ["F03"]),
            ("relative", relative, ["F05"]), ("dot-dot", dot_dot, ["F05"]),
        ]
        self.assertEqual(len(cases), 12)
        for label, make, want in cases:
            with self.subTest(label):
                root, w = self.fresh()
                vs = self.floor(w, cidfile=make(root, w))
                self.assertEqual(codes(vs), want, label)
                self.assertTrue(all(v.option == "--cidfile" for v in vs), label)
                self.assertFalse(any(root in str(v) or root in repr(v) for v in vs), label)
                if want == ["F04"] and label == "dangling-leaf":
                    self.assertFalse(os.path.exists(f"{root}/nowhere"), label)     # the link was never followed

    def test_an_invalid_schema_is_reported_and_nothing_is_read(self):
        s = schema_single(**{"--network": "host"})     # work dir /s/runs/kg-1 does not exist here: nothing is read
        self.assertEqual(G.check_mount_sources(s), G.check_schema(s))
        self.assertEqual(codes(G.check_mount_sources(s)), ["S02"])


class Static(unittest.TestCase):
    def test_the_filesystem_floor_reads_with_lstat_only(self):
        """It never follows a link: no stat, realpath, open, listdir or walk; lstat is its only read."""
        src = inspect.getsource(G._lstat_walk) + inspect.getsource(G._cidfile_code) + \
            inspect.getsource(G.check_mount_sources)
        for bad in ("os.stat(", "realpath", "open(", "listdir", "os.walk", "scandir", "readlink", "Path("):
            self.assertNotIn(bad, src, bad)
        self.assertIn("os.lstat(", src)

    def test_the_guard_never_joins_the_argv_or_splits_the_payload(self):
        src = inspect.getsource(G)
        for bad in ('" ".join', "' '.join", "join(argv", "shlex", "payload.split", "argv[-1].split", "print("):
            self.assertNotIn(bad, src, bad)

    def test_the_codes_are_stable(self):
        self.assertEqual(sorted(G.CODES), sorted(
            [f"S{n:02d}" for n in range(1, 20)] + ["G01", "G10", "G11", "G12", "G13", "G20", "G21", "G22", "G23",
                                                    "G30", "G31", "G32", "F01", "F02", "F03", "F04", "F05"]))


if __name__ == "__main__":
    unittest.main()
