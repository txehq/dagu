# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for kube_run.py and its pinned B5 copy (TXE-8039). kubeguard_test.go runs this file; directly:
    python3 -I -B test_kube_run.py -v                  (offline; HOME unchanged)

Two modes.
  - PURE, the default and what CI runs: every class except RealChildrenThroughB5. The fixture directory is a
    TemporaryDirectory, removed at module teardown. On a platform without B5's capabilities (anything but
    macOS), PlatformCustody also drives kube-run's REAL transport, and shows that it refuses (KR26) before any
    child exists.
  - REAL CHILDREN: RealChildrenThroughB5 runs only on macOS with KUBEGUARD_REAL_CHILDREN=1, and is skipped
    otherwise. It starts real, bounded, self-expiring children through B5. In this mode the fixture root is a
    mkdtemp directory, RETAINED UNCONDITIONALLY: its path is printed, and every leader, grandchild and escapee
    pid and every nonce is written there as soon as it is known. An assertion can fail before a child is
    confirmed, and those records are the evidence for reconciling every pid afterwards. Unconfirmed processes
    are appended to UNCONFIRMED.txt as they are found, and the module fails on any.

kube_run is imported from its file and driven through main() with explicit, owned inputs: a registry path,
a stub transport, a fixed clock, a minimal environ and byte streams. No test reaches a cluster or the network,
and no test runs kubectl. Every kubectl call goes to StubTransport, which records the argv and answers from a
script. The exception is RealChildrenThroughB5: its fixture "kubectl" is an owned /bin/sh script run through
kube-run's real transport (the pinned B5 copy), and it starts /bin/sleep, /usr/bin/head and, in two cases, a
python3 -I grandchild that calls setsid(). B5Reuse checks the B5 section against its pinned sha256 (the source
file, runner-final.py, is TXE-7974 evidence and not in this repository; see b5_custody.py).

Fixtures are inert data in the owned fixture directory (kubeguard-kr-*):
  - a fake kubeconfig with fake clusters (server https://127.0.0.1:9 and ...:10, never contacted);
  - a fake CA (random bytes, not a certificate);
  - a users section holding a SENTINEL "token" and an exec plugin whose command is a stub that would write a
    marker file if anything ran it.
The suite asserts that the sentinel never appears in kube-run's stdout or stderr, and that the marker never
exists.
"""
import base64
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import re
import secrets
import shutil
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent   # the code under test sits beside this file
# Real children run only where B5 works (macOS) and only when asked for explicitly.
REAL_CHILDREN = sys.platform == "darwin" and os.environ.get("KUBEGUARD_REAL_CHILDREN") == "1"
spec = importlib.util.spec_from_file_location("kube_run", HERE / "kube_run.py")
kr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kr)

SENTINEL = "SENTINEL-KR-FIXTURE-NOT-A-CREDENTIAL-91c2"
NOW = dt.datetime(2026, 11, 21, 8, 0, 0, tzinfo=dt.timezone.utc)
UID = "11111111-2222-3333-4444-555555555555"
OTHER_UID = "99999999-8888-7777-6666-555555555555"
CA = os.urandom(64)
OTHER_CA = os.urandom(64)
SERVER = "https://127.0.0.1:9"
OTHER_SERVER = "https://127.0.0.1:10"


def kubeconfig(server=SERVER, ca=CA, ctx_cluster="ci", insecure=False, extra_cluster="", users=None, head=""):
    b64 = base64.b64encode(ca).decode()
    other = base64.b64encode(OTHER_CA).decode()
    ins = "    insecure-skip-tls-verify: true\n" if insecure else ""
    users = users if users is not None else (
        "users:\n"
        "- name: ci-user\n"
        "  user:\n"
        f"    token: {SENTINEL}\n"
        "- name: oidc\n"
        "  user:\n"
        "    exec:\n"
        "      apiVersion: client.authentication.k8s.io/v1beta1\n"
        f"      command: {F.plugin}\n"
        f"      args: [\"get-token\", \"--secret={SENTINEL}\"]\n"
        "      env: []\n"
        "    client-key-data: |\n"
        f"      {SENTINEL}\n"
    )
    return (head +
            "apiVersion: v1\n"
            "clusters:\n"
            "- cluster:\n"
            f"    certificate-authority-data: {b64}\n"
            f"    server: {server}\n"
            f"{ins}"
            "  name: ci\n"
            "- cluster:\n"
            f"    certificate-authority-data: {other}\n"
            f"    server: {OTHER_SERVER}\n"
            "  name: other\n"
            f"{extra_cluster}"
            "contexts:\n"
            "- context:\n"
            f"    cluster: {ctx_cluster}\n"
            "    namespace: arc-runners\n"
            "    user: ci-user\n"
            "  name: txe-onprem-ci\n"
            "current-context: txe-onprem-ci\n"
            "kind: Config\n"
            "preferences: {}\n"
            + users)


class Fixture:
    def __init__(self):
        if REAL_CHILDREN:
            # mkdtemp, not TemporaryDirectory: nothing removes this directory implicitly (at garbage collection
            # or interpreter exit). With real children it is retained unconditionally, as evidence.
            self.tmp = None
            self.root = Path(tempfile.mkdtemp(prefix="kubeguard-kr-"))
            print(f"kubeguard fixture root (retained): {self.root}", file=sys.stderr, flush=True)
        else:
            self.tmp = tempfile.TemporaryDirectory(prefix="kubeguard-kr-")
            self.root = Path(self.tmp.name)
        self.unconfirmed = []   # (case, role, pid, state): owned processes not confirmed gone
        self.marker = self.root / "plugin-ran"
        self.plugin = self.root / "fake-oidc-plugin"
        self.plugin.write_text(f"#!/bin/sh\ntouch '{self.marker}'\nexit 97\n")
        self.plugin.chmod(self.plugin.stat().st_mode | stat.S_IXUSR)
        self.kc = self.root / "kubeconfig-ci.yaml"
        self.kubectl = str(self.root / "kubectl-never-run")
        self.registry = self.root / "kube-clusters.json"
        self.record = self.root / "record.json"

    def note(self, name, line):
        """Append one line to <root>/<name> at once, so the evidence survives an early assertion failure."""
        with open(self.root / name, "a") as f:
            f.write(line + "\n")

    def write_registry(self, **over):
        entry = {"production": False, "kubeconfig": str(self.kc), "context": "txe-onprem-ci", "server": SERVER,
                 "ca_sha256": hashlib.sha256(CA).hexdigest(), "uid": UID, "kubectl": self.kubectl,
                 "authorization": {"policy": "task-record"}}
        entry.update(over)
        entry = {k: v for k, v in entry.items() if v is not None}
        self.registry.write_text(json.dumps({"version": 2, "clusters": {"txe-onprem-ci": entry}}))

    def write_record(self, **over):
        rec = {"ticket": "TXE-8039", "cluster_id": "txe-onprem-ci", "verbs": ["get", "describe", "logs"],
               "resources": ["pods", "namespaces"], "namespaces": ["arc-runners"], "allow_identity_probe": True,
               "not_after": "2026-11-21T12:00:00Z", "authorized_by": "fixture"}
        rec.update(over)
        self.record.write_text(json.dumps(rec))


F = None


def setUpModule():
    global F
    F = Fixture()


def tearDownModule():
    """With real children, the fixture root is RETAINED UNCONDITIONALLY. Nothing is deleted, because an
    assertion can fail before confirm() records a child, and the recorded pids and nonces are the evidence for
    reconciliation afterwards. UNCONFIRMED.txt (case, role, pid, state; no arguments, no values) is appended
    as each unconfirmed process is found, and the module fails when there is any. In pure mode no child ever
    starts, and the TemporaryDirectory is removed."""
    try:
        plugin_ran = F.marker.exists()
        if F.unconfirmed:
            raise AssertionError(
                f"{len(F.unconfirmed)} owned process(es) not confirmed gone; evidence kept in {F.root}")
        assert not plugin_ran, "an exec plugin ran"
    finally:
        if F.tmp is not None:
            F.tmp.cleanup()


class StubTransport:
    """Records each call; answers probes with `uid` and requests with `request`."""

    def __init__(self, uid=UID, probe_rc=0, probe_timeout=False, request_timeout=False, during_probe=None):
        self.calls, self.uid, self.probe_rc = [], uid, probe_rc
        self.probe_timeout, self.request_timeout, self.during_probe = probe_timeout, request_timeout, during_probe

    def run(self, argv, env, timeout):
        self.calls.append((list(argv), dict(env), timeout))
        if "kube-system" in argv and "jsonpath={.metadata.uid}" in argv:
            if self.during_probe:
                self.during_probe()
            if self.probe_timeout:
                raise kr.Timeout()
            return self.probe_rc, (self.uid or "").encode(), b""
        if self.request_timeout:
            raise kr.Timeout()
        return 0, b"pod-a Running\n", b""


def call(args, transport=None, record=True, environ=None):
    t = transport or StubTransport()
    out, err = io.BytesIO(), io.BytesIO()
    argv = (["--authorization", str(F.record)] if record else []) + args
    env = environ if environ is not None else {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", ""),
                                               "KUBECONFIG": "/should/not/pass", "KUBECTL_X": "1"}
    rc = kr.main(argv, registry_path=str(F.registry), transport=t, now=NOW, environ=env, stdout=out, stderr=err)
    o, e = out.getvalue().decode(), err.getvalue().decode()
    assert SENTINEL not in o and SENTINEL not in e, "the sentinel leaked into output"
    return rc, o, e, t


ARGS = ["txe-onprem-ci", "--", "get", "pods", "-n", "arc-runners"]


class Base(unittest.TestCase):
    def setUp(self):
        F.kc.write_text(kubeconfig())
        F.write_registry()
        F.write_record()

    def refused(self, args, code, calls=0, transport=None, record=True, exit_code=3):
        rc, o, e, t = call(args, transport, record)
        self.assertEqual(rc, exit_code, e)
        self.assertIn(f"[{code} ", e)
        self.assertEqual(len(t.calls), calls, f"{code}: expected {calls} kubectl calls, saw {len(t.calls)}")
        self.assertEqual(o, "")
        return e


class HappyPath(Base):
    def test_verified_identity_then_the_request(self):
        rc, o, e, t = call(ARGS)
        self.assertEqual(rc, 0, e)
        self.assertEqual(o, "pod-a Running\n")
        self.assertEqual(len(t.calls), 2)
        probe, request = t.calls[0][0], t.calls[1][0]
        pin = [F.kubectl, "--kubeconfig", str(F.kc), "--context", "txe-onprem-ci"]
        self.assertEqual(probe[:5], pin)
        self.assertIn("--request-timeout=10s", probe)
        self.assertEqual(request, pin + ["get", "pods", "-n", "arc-runners"])
        for _, env, _ in t.calls:
            self.assertNotIn("KUBECONFIG", env)
            self.assertNotIn("KUBECTL_X", env)
            self.assertEqual(env["KUBERC"], "off")
        self.assertEqual(t.calls[0][2], kr.PROBE_TIMEOUT_S)
        self.assertEqual(t.calls[1][2], kr.DEFAULT_TIMEOUT_S)
        self.assertIn("identity=verified", e)

    def test_namespace_defaults_to_the_pinned_context(self):
        rc, _, e, _ = call(["txe-onprem-ci", "--", "get", "pods"])
        self.assertEqual(rc, 0, e)

    def test_timeout_option_bounds_the_request(self):
        rc, _, _, t = call(["--timeout", "30"] + ARGS)
        self.assertEqual((rc, t.calls[1][2]), (0, 30))

    def test_a_production_entry_has_no_special_route(self):
        # No hidden ceremony: an entry marked production follows the same configured-policy path.
        F.write_registry(production=True)
        rc, _, e, t = call(ARGS)
        self.assertEqual((rc, len(t.calls)), (0, 2), e)


class IdentityMismatchPreventsTheRequest(Base):
    def test_uid_mismatch_after_the_probe_stops_the_request(self):
        e = self.refused(ARGS, "KR16", calls=1, transport=StubTransport(uid=OTHER_UID))
        self.assertNotIn(OTHER_UID, e)
        self.assertNotIn(UID, e)

    def test_probe_failure_empty_or_timeout_stops_the_request(self):
        self.refused(ARGS, "KR15", calls=1, transport=StubTransport(probe_rc=1), exit_code=4)
        self.refused(ARGS, "KR15", calls=1, transport=StubTransport(uid=""), exit_code=4)
        self.refused(ARGS, "KR15", calls=1, transport=StubTransport(probe_timeout=True), exit_code=4)

    def test_kubeconfig_changed_during_the_probe_stops_the_request(self):
        def repoint():
            F.kc.write_text(kubeconfig(ctx_cluster="other"))
        self.refused(ARGS, "KR17", calls=1, transport=StubTransport(during_probe=repoint))

    def test_request_timeout(self):
        rc, _, e, t = call(ARGS, StubTransport(request_timeout=True))
        self.assertEqual((rc, len(t.calls)), (124, 2))
        self.assertIn("[KR18 ", e)


class PreContactPinsRefuseWithoutAProbe(Base):
    def test_server_mismatch(self):
        F.kc.write_text(kubeconfig(server=OTHER_SERVER))
        self.refused(ARGS, "KR12")

    def test_ca_mismatch(self):
        F.kc.write_text(kubeconfig(ca=OTHER_CA))
        self.refused(ARGS, "KR13")

    def test_context_repointed_to_another_cluster_in_the_same_file(self):
        F.kc.write_text(kubeconfig(ctx_cluster="other"))
        self.refused(ARGS, "KR12")

    def test_tls_verification_disabled(self):
        F.kc.write_text(kubeconfig(insecure=True))
        self.refused(ARGS, "KR14")

    def test_ca_from_a_file(self):
        ca_file = F.root / "ca.crt"
        ca_file.write_bytes(CA)
        text = kubeconfig().replace(f"certificate-authority-data: {base64.b64encode(CA).decode()}",
                                    "certificate-authority: ca.crt")
        F.kc.write_text(text)
        rc, _, e, _ = call(ARGS)
        self.assertEqual(rc, 0, e)
        ca_file.write_bytes(OTHER_CA)
        self.refused(ARGS, "KR13")

    def test_duplicate_or_missing_context_and_cluster(self):
        dup = ("- cluster:\n"
               f"    certificate-authority-data: {base64.b64encode(CA).decode()}\n"
               f"    server: {SERVER}\n"
               "  name: ci\n")
        F.kc.write_text(kubeconfig(extra_cluster=dup))
        self.refused(ARGS, "KR11")
        F.kc.write_text(kubeconfig(ctx_cluster="absent"))
        self.refused(ARGS, "KR11")
        F.write_registry(context="no-such-context")
        self.refused(ARGS, "KR11")

    def test_unsupported_kubeconfig_syntax_is_refused(self):
        for text in ('{"apiVersion": "v1"}\n',
                     kubeconfig().replace("    server: " + SERVER, "    server: &s " + SERVER),
                     kubeconfig().replace("clusters:\n", "clusters: [{}]\n", 1),
                     kubeconfig().replace("- context:\n", "- context: {cluster: ci}\n", 1),
                     kubeconfig() + "---\napiVersion: v1\n",
                     kubeconfig().replace("    server: " + SERVER, "\tserver: " + SERVER),
                     kubeconfig().replace("apiVersion: v1\n", "apiVersion: v1\nclusters:\n", 1),
                     "not yaml at all\n"):
            F.kc.write_text(text)
            self.refused(ARGS, "KR10")

    def test_unreadable_kubeconfig(self):
        F.write_registry(kubeconfig=str(F.root / "absent.yaml"))
        self.refused(ARGS, "KR10")

    def test_users_values_are_never_decoded(self):
        # Flow lists, block scalars and exec stanzas of OTHER users are stepped over, not parsed or run.
        rc, _, e, _ = call(ARGS)
        self.assertEqual(rc, 0, e)
        self.assertFalse(F.marker.exists())
        # Even syntax the reader would refuse in a parsed section passes when it belongs to another user:
        # kube-run reads only the pinned user's key names, never a value.
        F.kc.write_text(kubeconfig(users="users:\n- name: ci-user\n  user:\n    token: " + SENTINEL
                                   + "\n- name: x\n  user: {token: &a " + SENTINEL + "}\n"))
        rc, _, e, _ = call(ARGS)
        self.assertEqual(rc, 0, e)


class Authorization(Base):
    def test_unconfigured_policy_refuses_before_the_kubeconfig_is_opened(self):
        F.write_registry(authorization=None, kubeconfig=str(F.root / "absent.yaml"))
        self.refused(ARGS, "KR06")  # KR06, not KR10: the kubeconfig was never opened
        F.write_registry(authorization={"policy": "fido-signed"})  # not implemented: unconfigured
        self.refused(ARGS, "KR06")
        F.write_registry(authorization={})
        self.refused(ARGS, "KR06")

    def test_record_missing_invalid_expired_or_for_another_cluster(self):
        self.refused(ARGS, "KR07", record=False)
        F.record.write_text("not json")
        self.refused(ARGS, "KR07")
        F.write_record(not_after="2026-11-21T07:59:59Z")
        self.refused(ARGS, "KR07")
        F.write_record(not_after="2026-11-21 12:00")
        self.refused(ARGS, "KR07")
        F.write_record(cluster_id="staging")
        self.refused(ARGS, "KR07")
        F.write_record(ticket="")
        self.refused(ARGS, "KR07")
        F.write_record(verbs=[])
        self.refused(ARGS, "KR07")

    def test_the_identity_probe_must_itself_be_authorized(self):
        F.write_record(allow_identity_probe=False)
        self.refused(ARGS, "KR09")

    def test_request_outside_scope(self):
        self.refused(["txe-onprem-ci", "--", "delete", "pod", "x", "-n", "arc-runners"], "KR08")
        self.refused(["txe-onprem-ci", "--", "get", "secrets", "-n", "arc-runners"], "KR08")
        self.refused(["txe-onprem-ci", "--", "get", "pods,secrets", "-n", "arc-runners"], "KR08")
        self.refused(["txe-onprem-ci", "--", "get", "pods", "-n", "kube-system"], "KR08")
        self.refused(["txe-onprem-ci", "--", "get", "pods", "-A"], "KR08")
        F.write_record(namespaces=["*"])
        rc, _, e, _ = call(["txe-onprem-ci", "--", "get", "pods", "-A"])
        self.assertEqual(rc, 0, e)


class Arguments(Base):
    def test_overrides_are_refused_before_any_file_is_read(self):
        F.write_registry(kubeconfig=str(F.root / "absent.yaml"))
        for extra in (["--context", "txe-prod"], ["--kubeconfig=/x"], ["--server", "https://x"], ["-s", "x"],
                      [f"--token={SENTINEL}"], ["--as", "admin"], ["--as-group=g"], ["--user", "u"],
                      ["--cluster", "c"], ["--insecure-skip-tls-verify"], ["--certificate-authority=/x"],
                      ["--tls-server-name", "x"], ["--client-key", "/x"], ["--kuberc=/x"]):
            self.refused(ARGS + extra, "KR04")

    def test_unknown_or_ambiguous_requests(self):
        for kargs in (["foo-plugin", "x"], ["edit", "pod", "x"], ["-w", "get", "pods"], ["get"],
                      ["get", "pods", "-narc-runners"], ["get", "pods", "-n", "a", "-n", "b"],
                      ["get", "pods", "-n", "a", "-A"], ["get", "-f", "x.yaml"], ["get", "--bogus", "pods"]):
            self.refused(["txe-onprem-ci", "--"] + kargs, "KR05")

    def test_usage(self):
        for argv in ([], ["txe-onprem-ci"], ["txe-onprem-ci", "get", "pods"], ["txe-onprem-ci", "--"],
                     ["--registry", "/x", "txe-onprem-ci", "--", "get", "pods"],
                     ["--timeout", "0"] + ARGS, ["--timeout", "601"] + ARGS, ["--timeout", "x"] + ARGS):
            self.refused(argv, "KR01", record=False)

    def test_cluster_not_registered_and_bad_registry(self):
        e = self.refused(["Prod_Cluster", "--", "get", "pods"], "KR03")
        self.assertNotIn("Prod_Cluster", e)
        self.refused(["staging", "--", "get", "pods"], "KR03")
        F.registry.write_text("not json")
        self.refused(ARGS, "KR02")
        F.write_registry(uid="")
        self.refused(ARGS, "KR02")
        F.write_registry(ca_sha256="xyz")
        self.refused(ARGS, "KR02")
        F.write_registry(kubeconfig="relative.yaml")
        self.refused(ARGS, "KR02")

    def test_kubectl_must_be_found(self):
        # The registry must pin an absolute kubectl. The caller's PATH is never consulted, even when it holds a
        # kubectl (connector review of 2ce8d2d2: a PATH-selected binary could answer the probe and ignore the
        # request).
        bindir = F.root / "caller-bin"
        bindir.mkdir(exist_ok=True)
        fake = bindir / "kubectl"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o700)
        for pinned in (None, "kubectl", "bin/kubectl"):
            F.write_registry(kubectl=pinned)
            rc, _, e, t = call(ARGS, environ={"PATH": str(bindir)})
            self.assertEqual((rc, len(t.calls)), (3, 0), pinned)
            self.assertIn("[KR19 ", e)


class RequestScope(Base):
    """Every part of a request that selects a resource, a namespace or an operation is authorized (connector
    review of PR 298: multi-resource operands, cp's embedded namespace, all-namespaces spellings, auth and
    rollout subcommands)."""

    def scope(self, args, default="ctx-ns"):
        return kr.parse_request(args, default)

    def refused_by_parser(self, args):
        with self.assertRaises(kr.Refused) as cm:
            self.scope(args)
        self.assertEqual(cm.exception.code, "KR05", args)

    def test_every_resource_operand_is_authorized(self):
        self.assertEqual(self.scope(["get", "pods/a", "secrets/b"])["resources"], ["pods", "secrets"])
        self.assertEqual(self.scope(["get", "rc/web", "service/frontend", "pods/web-1"])["resources"],
                         ["rc", "service", "pods"])
        self.assertEqual(self.scope(["get", "pods", "a", "b"])["resources"], ["pods"])
        self.refused_by_parser(["get", "pods", "a", "secrets/b"])     # a typed operand after a bare type
        self.refused_by_parser(["get", "pods/a", "b"])                # a bare name inside a TYPE/NAME list
        # End to end: a record for pods does not cover a secrets operand, and nothing is contacted.
        self.refused(["txe-onprem-ci", "--", "get", "pods/a", "secrets/b", "-n", "arc-runners"], "KR08")
        rc, _, e, t = call(["txe-onprem-ci", "--", "get", "pods/a", "pods/b", "-n", "arc-runners"])
        self.assertEqual((rc, len(t.calls)), (0, 2), e)

    def test_label_and_annotation_values_are_not_resources(self):
        self.assertEqual(self.scope(["label", "pods", "a", "app.kubernetes.io/name=x", "team-"])["resources"],
                         ["pods"])
        self.assertEqual(self.scope(["annotate", "pods/a", "pods/b", "note=a/b"])["resources"], ["pods"])

    def test_a_cp_operand_naming_its_own_namespace_is_refused(self):
        self.refused_by_parser(["cp", "kube-system/pod-a:/etc/private", "/tmp/local-copy"])
        self.refused_by_parser(["cp", "/tmp/local", "kube-system/pod-a:/tmp/x"])
        r = self.scope(["cp", "pod-a:/etc/x", "/tmp/y", "-n", "arc-runners"])
        self.assertEqual((r["resources"], r["namespace"]), (["pods"], "arc-runners"))

    def test_every_true_spelling_of_all_namespaces(self):
        for a in ("-A", "--all-namespaces", "--all-namespaces=true", "--all-namespaces=TRUE", "--all-namespaces=True",
                  "--all-namespaces=1", "--all-namespaces=t", "--all-namespaces=T", "-A=true", "-A=1"):
            self.assertEqual(self.scope(["get", "pods", a])["namespace"], "*", a)
        for a in ("--all-namespaces=false", "--all-namespaces=0", "--all-namespaces=F", "-A=False"):
            self.assertEqual(self.scope(["get", "pods", a])["namespace"], "ctx-ns", a)
        for a in ("--all-namespaces=yes", "--all-namespaces=", "-A=on"):
            self.refused_by_parser(["get", "pods", a])
        self.refused(["txe-onprem-ci", "--", "get", "pods", "--all-namespaces=TRUE"], "KR08")

    def test_operands_after_the_terminator_are_authorized(self):
        # kubectl reads operands after `--` too (connector review of 1e1e974c).
        self.assertEqual(self.scope(["get", "pods/a", "--", "secrets/b"])["resources"], ["pods", "secrets"])
        self.refused_by_parser(["get", "pods", "--", "secrets/b"])
        self.refused_by_parser(["--", "get", "pods"])
        r = self.scope(["exec", "pod-a", "--", "get", "secrets/b"])      # exec: the pod's own command
        self.assertEqual((r["verb"], r["resources"]), ("exec", ["pods"]))
        self.refused(["txe-onprem-ci", "--", "get", "pods/a", "-n", "arc-runners", "--", "secrets/b"], "KR08")

    def test_an_attached_or_clustered_short_server_override_is_refused(self):
        # pflag reads `-sURL` and the cluster `-its` (= -i -t -s) as --server (connector review of 1e1e974c).
        for a in ("-shttps://other.example", "-s=https://x", "-its", "-ts"):
            self.assertTrue(kr.is_override(a), a)
        for a in ("-ojson", "-it", "-ojsonpath={.items[*].status}", "-v=5", "-lapp=s", "-A", "-w"):
            self.assertFalse(kr.is_override(a), a)
        self.refused(["txe-onprem-ci", "--", "get", "pods", "-shttps://other.example"], "KR04")

    def test_only_known_options_are_forwarded(self):
        # pflag reads `-wA` as -w -A (all namespaces) and `-inother` as -i -n other (connector review of
        # bcca1dcc). Unknown, attached and clustered options are refused instead of being forwarded unchecked.
        for args in (["get", "pods", "-wA"], ["exec", "pod-a", "-inother", "--", "id"], ["get", "pods", "-ojson"],
                     ["get", "pods", "--raw", "/api/v1/secrets"], ["get", "pods", "--frob=x"], ["-w", "get", "pods"]):
            self.refused_by_parser(args)
        r = self.scope(["get", "pods", "-w", "-o", "json", "--show-labels", "-l", "app=x", "--output=wide"])
        self.assertEqual((r["resources"], r["namespace"]), (["pods"], "ctx-ns"))
        self.assertEqual(self.scope(["exec", "-it", "pod-a", "--", "sh", "-c", "id"])["resources"], ["pods"])
        self.assertEqual(self.scope(["logs", "pod-a", "--tail", "10", "-f"])["resources"], ["pods"])
        self.refused(["txe-onprem-ci", "--", "get", "pods", "-wA"], "KR05")

    def test_file_based_and_create_requests_are_refused(self):
        # A manifest names its own kinds and namespaces, and `create <kind>` can be cluster-scoped (connector
        # review of 85bde125); neither can be read from the arguments before contact.
        for args in (["apply", "-f", "x.yaml"], ["create", "clusterrolebinding", "x", "--clusterrole", "admin"],
                     ["create", "-f", "x.yaml"], ["replace", "-f", "x.yaml"], ["diff", "-f", "x.yaml"],
                     ["delete", "-f", "x.yaml"], ["get", "pods", "-f", "x.yaml"], ["delete", "-k", "dir"],
                     ["get", "pods", "--filename=x.yaml"], ["apply", "-k", "dir"]):
            self.refused_by_parser(args)
        F.write_record(verbs=["apply", "create"], resources=["<files>", "clusterrolebindings"])
        self.refused(["txe-onprem-ci", "--", "apply", "-f", "x.yaml"], "KR05")

    def test_no_operand_verbs_and_subresources(self):
        # Connector review of 2ce8d2d2: `cluster-info dump` reads across namespaces, and --subresource is
        # authorized separately by the API.
        for args in (["cluster-info", "dump"], ["api-resources", "x"], ["version", "x"],
                     ["get", "pods", "--subresource=a/b"], ["get", "pods", "--subresource", "a", "--subresource=b"]):
            self.refused_by_parser(args)
        self.assertEqual(self.scope(["cluster-info"])["resources"], ["<discovery>"])
        self.assertEqual(self.scope(["patch", "pods/victim", "--subresource=ephemeralcontainers", "-p", "{}"])
                         ["resources"], ["pods/ephemeralcontainers"])
        self.assertEqual(self.scope(["get", "pods", "x", "--subresource", "status"])["resources"], ["pods/status"])
        F.write_record(verbs=["patch"])     # resources: pods, namespaces
        self.refused(["txe-onprem-ci", "--", "patch", "pods/victim", "--subresource=ephemeralcontainers", "-p", "{}",
                      "-n", "arc-runners"], "KR08")

    def test_auth_and_rollout_carry_their_subcommand(self):
        r = self.scope(["auth", "can-i", "get", "pods"])
        self.assertEqual((r["verb"], r["resources"]), ("auth can-i", ["selfsubjectaccessreviews"]))
        r = self.scope(["auth", "whoami"])
        self.assertEqual((r["verb"], r["resources"]), ("auth whoami", ["selfsubjectreviews"]))
        r = self.scope(["rollout", "restart", "deploy/x"])
        self.assertEqual((r["verb"], r["resources"]), ("rollout restart", ["deploy"]))
        for args in (["auth", "reconcile", "-f", "rbac.yaml"], ["auth"], ["auth", "--bogus", "can-i"],
                     ["rollout", "frobnicate", "deploy/x"], ["rollout"]):
            self.refused_by_parser(args)
        # End to end: a record granting "auth can-i" covers it, and never "auth reconcile".
        F.write_record(verbs=["auth can-i"], resources=["selfsubjectaccessreviews"])
        rc, _, e, t = call(["txe-onprem-ci", "--", "auth", "can-i", "get", "pods"])
        self.assertEqual((rc, len(t.calls)), (0, 2), e)
        self.refused(["txe-onprem-ci", "--", "auth", "reconcile", "-f", "rbac.yaml"], "KR05")
        F.write_record(verbs=["rollout status"], resources=["deploy"])
        self.refused(["txe-onprem-ci", "--", "rollout", "restart", "deploy/x"], "KR08")


class ValueFreeDiagnostics(Base):
    def test_no_value_from_the_command_or_files_appears_in_a_refusal(self):
        S = "SENTINELVALUE7d1"
        F.write_record(verbs=[S])
        cases = [
            ["txe-onprem-ci", "--", "get", "pods", f"--context={S}"],
            ["txe-onprem-ci", "--", f"{S}-plugin"],
            ["txe-onprem-ci", "--", "get", S, "-n", "arc-runners"],
            ["txe-onprem-ci", "--", "get", "pods", "-n", S],
            [S, "--", "get", "pods"],
            ["--timeout", S] + ARGS,
        ]
        for args in cases:
            rc, o, e, t = call(args)
            self.assertEqual(rc, 3, e)
            self.assertNotIn(S, e, args)
            self.assertNotIn(str(F.kc), e)
            self.assertNotIn(SERVER, e)
            self.assertEqual(t.calls, [])


class RaisingTransport(StubTransport):
    """A stub whose probe or request raises one of B5Transport's outcomes."""

    def __init__(self, probe_exc=None, request_exc=None):
        super().__init__()
        self.probe_exc, self.request_exc = probe_exc, request_exc

    def run(self, argv, env, timeout):
        self.calls.append((list(argv), dict(env), timeout))
        exc = self.probe_exc if "kube-system" in argv else self.request_exc
        if exc:
            raise exc
        return (0, UID.encode(), b"") if "kube-system" in argv else (0, b"ok\n", b"")


class SettlementOutcomesInKubeRun(Base):
    def test_an_unproven_probe_settlement_never_unlocks_the_request(self):
        e = self.refused(ARGS, "KR22", calls=1, exit_code=5,
                         transport=RaisingTransport(probe_exc=kr.Unsettled("capture truncated: x")))
        self.assertIn("nothing further was run", e)

    def test_unsettled_request(self):
        rc, o, e, t = call(ARGS, RaisingTransport(request_exc=kr.Unsettled("reason withheld")))
        self.assertEqual((rc, len(t.calls)), (5, 2))
        self.assertIn("[KR22 ", e)

    def test_output_over_bound_and_signal(self):
        self.refused(ARGS, "KR20", calls=1, transport=RaisingTransport(probe_exc=kr.OutputOverBound()))
        e = self.refused(ARGS, "KR21", calls=1, exit_code=6, transport=RaisingTransport(probe_exc=kr.Stopped("x")))
        self.assertIn("UNKNOWN", e)


# ---- the B5 reuse: pinned, unchanged, and mapped (pure) ---------------------------------------------------
# The B5 section of runner-final.py (TXE-7974 evidence, sha256 c7c97084..., lines 294-640), by its own sha256.
# The source file is not in this repository, so the section is pinned by hash; b5_custody.py records where
# it came from.
B5_SECTION_SHA256 = "074c8f65f57b987118079e99ef92c9ec86929111679605a2552c9c8fd1ff94d8"


def b5_section(text):
    """From the line that starts "# ---------- B5" to the line that starts "# ---------- B3" (or the end).
    Anchored at line starts: b5_custody.py's docstring quotes the marker mid-line."""
    start = re.search(r"^# ---------- B5", text, re.M).start()
    end = re.search(r"^# ---------- B3", text[start:], re.M)
    return text[start:] if end is None else text[start:start + end.start()]


class B5Reuse(unittest.TestCase):
    def test_the_copy_is_the_pinned_file_and_its_section_is_runner_finals(self):
        data = (HERE / "b5_custody.py").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), kr.B5_SHA256)
        ours = b5_section(data.decode())
        self.assertEqual(hashlib.sha256(ours.encode()).hexdigest(), B5_SECTION_SHA256)

    def test_a_copy_that_is_not_the_pinned_one_is_refused(self):
        d = F.root / "b5-tampered"
        d.mkdir(exist_ok=True)
        (d / "b5_custody.py").write_bytes((HERE / "b5_custody.py").read_bytes() + b"\n# edited\n")
        with self.assertRaises(kr.Refused) as cm:
            kr.load_b5(str(d))
        self.assertEqual(cm.exception.code, "KR25")
        with self.assertRaises(kr.Refused):
            kr.load_b5(str(F.root / "absent-dir"))

    def test_b5_reasons_are_shown_only_when_they_are_b5s_own(self):
        self.assertEqual(kr.b5_why("x\npid 12 pgid 12: membership unknown (y): nothing more is signalled"),
                         "pid 12 pgid 12: membership unknown (y): nothing more is signalled")
        self.assertTrue(kr.b5_why("capture truncated: a pipe was still held").startswith("capture truncated"))
        self.assertEqual(kr.b5_why(f"error: server https://10.0.0.1 said {SENTINEL}"), "reason withheld")
        self.assertEqual(kr.b5_why(""), "reason withheld")

    def test_the_transport_maps_b5s_codes(self):
        class FakeB5:
            def __init__(self, result):
                self.result, self.seen = result, None

            def bounded_run(self, cmd, timeout, env):
                self.seen = (cmd, timeout, env)
                return self.result

        t = kr.B5Transport(FakeB5((0, "out", "err")))
        self.assertEqual(t.run(("/k", "get"), {"PATH": "/bin"}, 30), (0, b"out", b"err"))
        self.assertEqual(t.b5.seen, (["/k", "get"], 30, {"PATH": "/bin"}))
        with self.assertRaises(kr.Timeout):
            kr.B5Transport(FakeB5((124, "", "timeout"))).run(["/k"], {}, 1)
        with self.assertRaises(kr.OutputOverBound):
            kr.B5Transport(FakeB5((125, "", "\noutput over the 4194304-byte cap"))).run(["/k"], {}, 1)
        with self.assertRaises(kr.Unsettled) as cm:
            kr.B5Transport(FakeB5((125, "", "kubectl said things\npid 9 pgid 9: the leader did not exit"))).run(
                ["/k"], {}, 1)
        self.assertTrue(cm.exception.cause.startswith("pid 9 pgid 9"))
        with self.assertRaises(kr.PlatformUnsupported):
            kr.B5Transport(FakeB5((125, "", "refused before any child: this platform lacks ['x']"))).run(
                ["/k"], {}, 1)


class PlatformCustody(Base):
    """B5 needs macOS. Elsewhere its refusal before any child must surface as KR26, after every pre-contact
    check, with nothing run."""

    def go(self, transport=None):
        out, err = io.BytesIO(), io.BytesIO()
        rc = kr.main(["--authorization", str(F.record)] + ARGS, registry_path=str(F.registry), now=NOW,
                     environ={"PATH": "/usr/bin:/bin"}, transport=transport, stdout=out, stderr=err)
        return rc, out.getvalue().decode(), err.getvalue().decode()

    def test_b5s_refusal_before_any_child_is_kr26(self):
        class RefusingB5:
            def __init__(self):
                self.calls = 0

            def bounded_run(self, cmd, timeout, env):
                self.calls += 1
                return 125, "", "refused before any child: this platform lacks ['libproc proc_listpids (OSError)']"

        b5 = RefusingB5()
        rc, o, e = self.go(kr.B5Transport(b5))
        self.assertEqual((rc, o, b5.calls), (3, "", 1), e)
        self.assertIn("[KR26 custody-unsupported-on-this-platform]", e)
        self.assertIn("no process was started", e)

    @unittest.skipIf(sys.platform == "darwin", "macOS has B5's capabilities; RealChildrenThroughB5 covers it")
    def test_off_macos_the_real_transport_refuses_before_any_child(self):
        # kube-run's REAL transport: the pinned b5_custody.py, loaded from this directory. The fixture "kubectl"
        # would leave a marker if anything ran it.
        ran = F.root / "kubectl-ran"
        fake = F.root / "kubectl-platform"
        fake.write_text(f"#!/bin/sh\ntouch '{ran}'\nexit 0\n")
        fake.chmod(0o700)
        F.write_registry(kubectl=str(fake))
        rc, o, e = self.go()
        self.assertEqual((rc, o), (3, ""), e)
        self.assertIn("[KR26 ", e)
        self.assertIn("the identity probe", e)
        self.assertFalse(ran.exists(), "a child ran on a platform B5 does not support")


class CredentialHelpersAreRefused(Base):
    def target_user(self, body):
        users = ("users:\n"
                 "- name: ci-user\n"
                 "  user:\n" + body +
                 "- name: other\n"
                 "  user:\n"
                 f"    token: {SENTINEL}\n")
        F.kc.write_text(kubeconfig(users=users))

    def test_exec_auth_provider_and_impersonation_are_refused_before_any_call(self):
        for body in ("    exec:\n      command: /x\n      args: [\"a\"]\n",
                     "    auth-provider:\n      name: oidc\n",
                     f"    token: {SENTINEL}\n    as: admin\n",
                     "    unknown-key: x\n"):
            self.target_user(body)
            self.refused(ARGS, "KR23")

    def test_static_credentials_pass_and_their_values_are_never_shown(self):
        for body in (f"    token: {SENTINEL}\n", "    client-certificate-data: QUJD\n    client-key-data: |\n      x\n",
                     "    tokenFile: /x\n"):
            self.target_user(body)
            rc, _, e, _ = call(ARGS)
            self.assertEqual(rc, 0, e)

    def test_a_user_layout_the_reader_cannot_place_is_refused(self):
        F.kc.write_text(kubeconfig(users="users:\n- name: ci-user\n  user: {token: x}\n"))
        self.refused(ARGS, "KR10")
        F.kc.write_text(kubeconfig(users="users:\n- name: someone-else\n  user:\n    token: x\n"))
        self.refused(ARGS, "KR10")


# ---- REAL children through B5 (8 fixtures; macOS with KUBEGUARD_REAL_CHILDREN=1 only, never in CI). --------
# Every fixture "kubectl" is an owned /bin/sh script in the temp directory that writes its own pid ($$) and any
# child's pid ($!) to marker files there; the test reads those exact pids back. Every child and grandchild
# expires on its own (/bin/sleep <= 10, escapees <= 5 s), so a failed kill leaks a bounded sleeper, never a
# daemon. THE TESTS SIGNAL NO CHILD OR DESCENDANT; only kube-run (through B5) does. The tests' own signal calls
# are exactly two: identity()'s os.kill(pid, 0), a signal-0 existence probe that delivers nothing; and fixture 8's
# self-sent SIGTERM to the TEST process (os.getpid()), which drives kube-run's outer stop path.
#
# Identity, in three states:
#   GONE      os.kill(pid, 0) raises ProcessLookupError: no process holds the pid.
#   RECYCLED  the pid exists, and libproc proc_pidpath reads a DIFFERENT executable from the owned process's
#             known one (/bin/sleep for a sleeper). /bin/sleep is NOT unique to this test, but a sleeper never
#             execs, so a different executable at its pid shows that the owned sleeper ended. The SAME path at
#             that pid stays UNKNOWN: it may be ours or an unrelated sleep. Neither state authorizes a signal.
#   UNKNOWN   anything else. That includes a failed or empty proc_pidpath, a PermissionError, a /bin/sh leader
#             still listed (macOS /bin/sh re-execs, so its path is no identity), and an escapee pid: the
#             escapee runs the SHARED interpreter, so its path cannot tell it from an unrelated python.
# An escapee is confirmed only by its completion handshake: as its last act it writes "<nonce> <pid>" to a
# done-marker, with a per-test nonce the test generated. After that it exits, and its pid must then read GONE
# within a short bound. Any UNKNOWN is appended at once to <root>/UNCONFIRMED.txt and F.unconfirmed, and the
# case fails. The fixture root is retained unconditionally. No kubectl, no credential plugin, no network.
import ctypes  # noqa: E402

_libproc = None
if sys.platform == "darwin":
    _libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    _libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    _libproc.proc_pidpath.restype = ctypes.c_int


def exe_of(pid):
    """The executable path at pid, or None when it cannot be read (always None off macOS: UNKNOWN, never GONE)."""
    if _libproc is None:
        return None
    buf = ctypes.create_string_buffer(4096)
    n = _libproc.proc_pidpath(pid, buf, 4096)
    return os.path.realpath(buf.value.decode()) if n > 0 else None


def identity(pid, unique_exe=None):
    """GONE, RECYCLED or UNKNOWN (see the protocol above). `unique_exe` (the name is historical) is the owned
    process's KNOWN, never-exec'ing executable (/bin/sleep). It is not unique to this test: a DIFFERENT path
    at the pid means the owned process ended (RECYCLED), and the SAME path is UNKNOWN. None means only GONE
    confirms."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "GONE"
    except PermissionError:
        return "UNKNOWN"
    if unique_exe is None:
        return "UNKNOWN"
    current = exe_of(pid)
    if current is None:
        return "UNKNOWN"          # a failed identity read is never proof of exit
    return "RECYCLED" if current != os.path.realpath(unique_exe) else "UNKNOWN"


def confirmed(state):
    return state in ("GONE", "RECYCLED")


def settle_state(pid, unique_exe=None, within=0.0):
    """identity(), polled for at most `within` seconds until it confirms. Never signals."""
    end = time.monotonic() + within
    state = identity(pid, unique_exe)
    while not confirmed(state) and time.monotonic() < end:
        time.sleep(0.05)
        state = identity(pid, unique_exe)
    return state


SH, SLEEP, HEAD = "/bin/sh", "/bin/sleep", "/usr/bin/head"
PYEXE = os.path.realpath(sys.executable)
# B5's own bounds: TERM grace + KILL grace + drain, plus scheduling slack.
SETTLE_MARGIN_S = 2.0 + 3.0 + 0.5 + 2.0


@unittest.skipUnless(REAL_CHILDREN, "real children through B5: macOS with KUBEGUARD_REAL_CHILDREN=1 only")
class RealChildrenThroughB5(Base):
    """The 8 real-child fixtures. kube-run runs with its REAL transport (B5Transport, the pinned copy)."""

    ESCAPEE_LIFE_S = 5
    HANDSHAKE_WAIT_S = 5 + 4      # its whole life plus slack; then 2 s more for the pid to read GONE
    EXIT_WAIT_S = 2

    def setUp(self):
        super().setUp()
        self.d = Path(tempfile.mkdtemp(prefix="case-", dir=F.root))
        self.leaders = self.d / "leaders"
        self.gc = self.d / "grandchild.pid"
        self.esc = self.d / "escapee.pid"
        self.done = self.d / "escapee.done"
        self.req = self.d / "request-ran"
        self.nonce = secrets.token_hex(16)
        self.escapee_started = False
        # Recorded before anything runs. The shell scripts write the leader ($$), grandchild ($!) and escapee
        # (getpid after setsid) pids into this case directory as their first act.
        F.note("cases.txt", f"{self._testMethodName} dir={self.d.name} nonce={self.nonce}")

    def unconfirmed(self, role, pid, state):
        F.unconfirmed.append((self._testMethodName, role, pid, state))
        F.note("UNCONFIRMED.txt", f"{self._testMethodName} {role} pid={pid} state={state}")

    def confirm(self, role, pid, unique_exe=None, within=0.0):
        """Assert an owned process is gone. If it is not confirmed, record it at once (UNCONFIRMED.txt) and
        fail. Never signals."""
        state = settle_state(pid, unique_exe, within)
        if not confirmed(state):
            self.unconfirmed(role, pid, state)
        self.assertTrue(confirmed(state), f"{role} pid {pid}: {state}")

    def tearDown(self):
        # An escapee is never signalled. Wait for its handshake, then for its pid to read GONE.
        if not self.escapee_started:
            return
        pid = int(self.esc.read_text()) if self.esc.exists() and self.esc.read_text().strip().isdigit() else None
        end = time.monotonic() + self.HANDSHAKE_WAIT_S
        while time.monotonic() < end and not self.done.exists():
            time.sleep(0.05)
        expect = f"{self.nonce} {pid}"
        ok = pid is not None and self.done.exists() and self.done.read_text().strip() == expect
        if not ok:
            self.unconfirmed("escapee", pid, "NO-HANDSHAKE")
            self.fail(f"escapee pid {pid}: no completion handshake within {self.HANDSHAKE_WAIT_S} s")
        # The handshake is its last act before exit; its pid must now vanish (GONE). Its executable is the
        # shared interpreter, so RECYCLED cannot be told apart from it: only GONE confirms.
        self.confirm("escapee", pid, None, self.EXIT_WAIT_S)

    def script(self, probe_body, request_body):
        p = self.d / "kubectl-fixture"
        p.write_text("#!/bin/sh\n"
                     f"echo $$ >> '{self.leaders}'\n"
                     'case "$*" in\n'
                     f"  *kube-system*) {probe_body} ;;\n"
                     f"  *) echo x > '{self.req}'; {request_body} ;;\n"
                     "esac\n")
        p.chmod(0o700)
        F.write_registry(kubectl=str(p))

    def go(self, argv=ARGS):
        t0 = time.monotonic()
        out, err = io.BytesIO(), io.BytesIO()
        rc = kr.main(["--authorization", str(F.record)] + argv, registry_path=str(F.registry), now=NOW,
                     environ={"PATH": "/usr/bin:/bin"}, stdout=out, stderr=err)
        e = err.getvalue().decode()
        self.assertNotIn(SENTINEL, out.getvalue().decode() + e)
        return rc, out.getvalue().decode(), e, time.monotonic() - t0

    def leader_pids(self):
        return [int(x) for x in self.leaders.read_text().split()] if self.leaders.exists() else []

    def escape(self, hold_pipes):
        """A python grandchild that calls setsid() (leaving the group) and records its own pid. It then sleeps
        ESCAPEE_LIFE_S and, as its LAST act, writes "<nonce> <pid>" to the done-marker and exits (the
        completion handshake). The shell waits (at most 5 s) for the pid record, so the escape happens before
        the shell exits."""
        self.escapee_started = True
        redirect = "" if hold_pipes else " </dev/null >/dev/null 2>&1"
        code = (f"import os, time; os.setsid(); p = os.getpid(); f = open('{self.esc}', 'w'); f.write(str(p)); "
                f"f.close(); time.sleep({self.ESCAPEE_LIFE_S}); "
                f"g = open('{self.done}', 'w'); g.write('{self.nonce} ' + str(p)); g.close()")
        return (f"{PYEXE} -I -c \"{code}\"{redirect} & "
                f"n=0; while [ ! -s '{self.esc}' ] && [ $n -lt 100 ]; do {SLEEP} 0.05; n=$((n+1)); done")

    def test_1_probe_and_request_settle_and_every_leader_is_gone(self):
        self.script(f"echo {UID}", "echo pod-a")
        rc, out, e, _ = self.go()
        self.assertEqual((rc, out), (0, "pod-a\n"), e)
        pids = self.leader_pids()
        self.assertEqual(len(pids), 2)
        for pid in pids:
            self.confirm("leader", pid, None, 1.0)

    def test_2_a_grandchild_holding_stdout_is_settled_with_its_group(self):
        self.script(f"echo {UID}", f"{SLEEP} 10 & echo $! > '{self.gc}'; echo pod-a")
        rc, out, e, took = self.go()
        self.assertEqual((rc, out), (0, "pod-a\n"), e)
        self.confirm("grandchild", int(self.gc.read_text()), SLEEP, 2.0)
        self.assertLess(took, SETTLE_MARGIN_S + 2)

    def test_3_a_request_past_its_timeout_ends_its_whole_group(self):
        self.script(f"echo {UID}", f"{SLEEP} 10 & echo $! > '{self.gc}'; {SLEEP} 10")
        rc, _, e, took = self.go(["--timeout", "1"] + ARGS)
        self.assertEqual(rc, 124, e)
        self.assertIn("[KR18 ", e)
        self.confirm("grandchild", int(self.gc.read_text()), SLEEP, 2.0)
        for pid in self.leader_pids():
            self.confirm("leader", pid, None, 1.0)
        self.assertLess(took, 1 + SETTLE_MARGIN_S)

    def test_4_a_child_that_ignores_term_is_killed(self):
        self.script(f"echo {UID}", f"trap '' TERM; {SLEEP} 10 & echo $! > '{self.gc}'; {SLEEP} 10")
        rc, _, e, took = self.go(["--timeout", "1"] + ARGS)
        self.assertEqual(rc, 124, e)
        self.confirm("grandchild", int(self.gc.read_text()), SLEEP, 2.0)
        for pid in self.leader_pids():
            self.confirm("leader", pid, None, 1.0)
        self.assertLess(took, 1 + SETTLE_MARGIN_S)

    def test_5_an_escapee_holding_the_probes_pipe_is_refused_and_never_unlocks_the_request(self):
        # The escapee is not signalled by anyone; tearDown waits for its handshake and its exit.
        self.script(f"{self.escape(hold_pipes=True)}; echo {UID}", "echo pod-a")
        rc, out, e, _ = self.go()
        self.assertEqual(rc, 5, e)
        self.assertIn("[KR22 ", e)
        self.assertIn("capture truncated", e)
        self.assertFalse(self.req.exists(), "the request ran after an unproven probe")
        self.assertEqual(out, "")

    def test_6_LIMIT_an_escapee_with_closed_pipes_is_invisible_to_b5(self):
        # The stated B5 limit, shown rather than hidden: the call completes, and the escapee still runs.
        # kube-run's answer is to refuse the only descendant kubectl is known to start (KR23, credential helpers).
        # tearDown then confirms its self-expiry by the handshake, without signalling it.
        self.script(f"echo {UID}", f"{self.escape(hold_pipes=False)}; echo pod-a")
        rc, out, e, _ = self.go()
        self.assertEqual((rc, out), (0, "pod-a\n"), e)
        self.assertFalse(self.done.exists(), "the escapee finished before the call returned; the limit is not shown")
        self.assertNotEqual(identity(int(self.esc.read_text())), "GONE",
                            "expected the escapee to be invisible to B5 and still alive")

    def test_7_output_over_the_cap_is_refused(self):
        self.script(f"echo {UID}", f"{HEAD} -c 5000000 /dev/zero")
        rc, out, e, _ = self.go()
        self.assertEqual(rc, 3, e)
        self.assertIn("[KR20 ", e)
        self.assertEqual(out, "")
        for pid in self.leader_pids():
            self.confirm("leader", pid, None, 1.0)

    def test_8_an_outer_stop_signal_settles_the_running_group(self):
        self.script(f"echo {UID}", f"{SLEEP} 10 & echo $! > '{self.gc}'; {SLEEP} 10")
        before = signal.getsignal(signal.SIGTERM)
        timer = threading.Timer(1.0, os.kill, (os.getpid(), signal.SIGTERM))
        timer.start()
        try:
            rc, _, e, took = self.go()
        finally:
            timer.cancel()
        self.assertEqual(rc, 6, e)
        self.assertIn("[KR21 ", e)
        self.assertIs(signal.getsignal(signal.SIGTERM), before)
        self.confirm("grandchild", int(self.gc.read_text()), SLEEP, 2.0)
        for pid in self.leader_pids():
            self.confirm("leader", pid, None, 1.0)
        self.assertLess(took, 1 + SETTLE_MARGIN_S)


class ReaderUnits(unittest.TestCase):
    def test_sections_parse_kubectl_style_and_indented_style(self):
        F.kc.write_text("")
        text = kubeconfig(users="users: []\n")
        sec = kr.read_sections(text.encode())
        self.assertEqual([c["name"] for c in sec["clusters"]], ["ci", "other"])
        self.assertEqual(sec["contexts"][0]["context"]["cluster"], "ci")
        indented = text.replace("\n- ", "\n  - ").replace("\n    ", "\n      ").replace("\n  name", "\n    name")
        sec2 = kr.read_sections(indented.encode())
        self.assertEqual(sec2["clusters"][0]["cluster"]["server"], SERVER)

    def test_quoted_scalars(self):
        text = kubeconfig(users="").replace(f"    server: {SERVER}", f"    server: \"{SERVER}\"", 1) \
            .replace("  name: txe-onprem-ci", "  name: 'txe-onprem-ci'")
        sec = kr.read_sections(text.encode())
        self.assertEqual(sec["clusters"][0]["cluster"]["server"], SERVER)
        self.assertEqual(sec["contexts"][0]["name"], "txe-onprem-ci")

    def test_fixture_constructor_sets_every_attribute(self):
        # A helper once inserted mid-constructor left these attributes unset, and every Base.setUp failed with
        # AttributeError before any child ran (TXE-8039). This names that class of setup failure directly. It uses no Base.setUp, starts no process, and only
        # reads attributes and paths the constructor made inside its own mkdtemp root.
        for name in ("root", "unconfirmed", "marker", "plugin", "kc", "kubectl", "registry", "record"):
            self.assertTrue(hasattr(F, name), f"Fixture.__init__ did not set {name}")
        self.assertTrue(F.root.is_dir())
        self.assertEqual(F.unconfirmed, [])
        for path in (F.marker, F.plugin, F.kc, F.registry, F.record):
            self.assertEqual(path.parent, F.root)
        self.assertEqual(Path(F.kubectl).parent, F.root)
        self.assertTrue(F.plugin.is_file() and os.access(F.plugin, os.X_OK))
        self.assertFalse(F.marker.exists())


if __name__ == "__main__":
    unittest.main()
