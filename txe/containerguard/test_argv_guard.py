# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for argv_guard.py (TXE-8041). containerguard_test.go runs this file; directly:
    python3 -I -B test_argv_guard.py -v

Pure: no process, no file, no network. The argv and schema below model a real run (TXE-8039's KG-r3 kubeguard run),
written out here independently of any runner. Every credential-looking value is a FAKE sentinel.
"""
import dataclasses
import importlib.util
import inspect
import random
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


class Static(unittest.TestCase):
    def test_the_guard_never_joins_the_argv_or_splits_the_payload(self):
        src = inspect.getsource(G)
        for bad in ('" ".join', "' '.join", "join(argv", "shlex", "payload.split", "argv[-1].split", "print("):
            self.assertNotIn(bad, src, bad)

    def test_the_codes_are_stable(self):
        self.assertEqual(sorted(G.CODES), sorted(
            [f"S{n:02d}" for n in range(1, 18)] + ["G01", "G10", "G11", "G12", "G13", "G20", "G21", "G22", "G23",
                                                    "G30", "G31", "G32"]))


if __name__ == "__main__":
    unittest.main()
