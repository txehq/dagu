#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""kube-run (TXE-8039): one kubectl call, bound to a registered cluster's identity. It runs kubectl through the
reviewed B5 host custody (b5_custody.py, pinned by sha256). This is source only: nothing installs or wires it.

    kube-run [--authorization FILE] [--timeout SECONDS] <cluster-id> -- <kubectl arguments>

Why: on 2026-11-21 at 07:14:57Z an agent's `kubectl get ... -A` with no --context read the PRODUCTION
cluster, because that workstation's default context is production. Naming a context is not enough: a context name
is a local alias, the same name can mean another cluster in another file, and a context can be repointed
inside its file. kube-run binds the call to the cluster itself.

What it does, in order. Each step fails closed, and no step contacts a cluster until every earlier one passed:

 1. ARGUMENTS. The caller names a registry cluster id, never a kubeconfig or context. Arguments that pick
    or change the target, the identity or TLS (--kubeconfig, --context, --server/-s, --cluster, --user,
    --token, --as*, --username, --password, --certificate-authority, --client-*, --tls-server-name,
    --insecure-skip-tls-verify, --kuberc) are refused. The verb, resources and namespace are read from the
    arguments. A plugin, an unknown verb or an ambiguous flag is refused.
 2. REGISTRY. The entry for the id gives the pinned kubeconfig path, context, server URL, CA SHA-256 and
    kube-system Namespace UID. The registry path is fixed (~/.coding_global/kube-clusters.json); the CLI
    cannot point it elsewhere.
 3. AUTHORIZATION, through a separate interface (authorize() below). The entry's "authorization.policy"
    names the policy. When it is absent or names no implemented policy, the call is refused as
    UNCONFIGURED. This file sets no deployment policy and no grant classes, and treats production like any
    other entry: its authorization is whatever the deployed registry says. The one implemented policy,
    "task-record", checks a task authorization record (ticket, cluster, verbs, resources, namespaces, expiry,
    authorized_by) against the request AND against the identity probe. The probe is itself an API read, so
    it must be authorized explicitly (allow_identity_probe). A record is a declaration of scope, not proof
    of authority: who may issue one is deployment policy, and is not decided here. Ordering: the "is a
    policy configured" check runs before the kubeconfig is opened. The scope check runs right after step 4,
    because a request without -n takes the pinned context's namespace. Both run before any contact.
 4. PRE-CONTACT PINS, from the kubeconfig as inert data. The file is read into memory as bytes and hashed.
    Its top-level sections are found by a restricted line reader. Only the "clusters" and "contexts"
    sections are parsed into values. In "users", kube-run reads two things: each item's `name`, to find the
    user the pinned context names, and the KEY NAMES directly under that user's `user:` mapping (user_keys).
    It never decodes a value there (token, key data or exec arguments). Every other section is stepped over
    line by line by indentation. Its lines are in memory, because the whole file was read, but they are
    never decoded into values, compared, logged or passed anywhere. A user whose keys are not all static
    credentials (token, tokenFile, client-certificate(-data), client-key(-data), username, password) is
    refused (KR23). That covers exec, auth-provider and impersonation, because a credential helper is a
    descendant B5 cannot follow once it leaves the process group. Nothing in the
    file is executed: no exec plugin and no auth provider. The reader is this file's own, a restricted
    subset of YAML block syntax (no PyYAML; stdlib only). It refuses anchors, aliases, tags, flow
    collections, block scalars, multiple documents, JSON and tabs inside the sections it parses, and any
    top-level line it cannot place. The context must resolve to exactly one cluster, whose server must equal
    the pinned server and whose CA must hash to the pinned SHA-256. TLS verification must not be disabled.
    A mismatch here refuses with NO contact: no probe and no request.
 5. IDENTITY PROBE. kubectl, with the pinned --kubeconfig and --context, reads the kube-system Namespace
    UID. TLS is verified by kubectl against the CA that step 4 pinned, so the read can only reach that
    cluster. It is bounded by --request-timeout and B5's bounded_run (see B5Transport's stated limit). The UID must
    equal the pinned one.
    A mismatch, an error, an empty answer or a timeout refuses the request, which is then never made.
 6. REQUEST. The kubeconfig bytes are hashed again. If the file changed since step 4, the request is not
    made. Otherwise kubectl runs once with the pinned --kubeconfig and --context and the caller's arguments,
    in an environment without KUBECONFIG and with KUBERC=off, bounded by --timeout (default 120 s, at most
    600 s), B5's per-stream output cap (4 MiB) and B5's settlement. Its stdout and stderr are passed through, and its
    exit status is
    kube-run's.

Diagnostics are stable codes (KRnn) with field names only. Values are withheld: no path, context, server,
CA, UID, argument text or record content. The cluster id appears only after it has matched a registry id.

Exit status: kubectl's own on a completed request; 3 refused; 4 identity probe failed; 5 processes NOT
confirmed stopped (settlement UNKNOWN; nothing further runs); 6 stopped by a signal; 124 request timed out.

B5 proves settlement of the OWNED group only. An escaped (setsid) descendant is neither seen nor signalled, and
shows only as a truncated capture while it holds a pipe. Credential helpers are therefore refused (KR23), and
kube-run is not ready for real auth plugins. It is not containment for arbitrary exec plugins or client-go
programs.

Platform: B5 needs macOS (libproc proc_listpids, and os.waitid with WNOWAIT, which needs Python 3.13 there).
Elsewhere, B5 refuses before it creates any child, and kube-run refuses that call as KR26 (exit 3). Steps 1 to 4
still run first, so a refusal there keeps its own code.

Residual gaps, stated: a single local user can edit the registry, this file and the kubeconfig, so this is a
reviewed guard and not a security boundary. There is a window between the step-6 hash and kubectl reading
the file; the hash narrows it but cannot close it.
"""
import base64
import binascii
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import types

REGISTRY_PATH = os.path.expanduser("~/.coding_global/kube-clusters.json")
PROBE_REQUEST_TIMEOUT = "10s"
PROBE_TIMEOUT_S = 30
DEFAULT_TIMEOUT_S = 120
MAX_TIMEOUT_S = 600
KILL_GRACE_S = 5
EXIT_REFUSED, EXIT_PROBE, EXIT_UNSETTLED, EXIT_STOPPED, EXIT_TIMEOUT = 3, 4, 5, 6, 124
CLUSTER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

CODES = {
    "KR01": "usage", "KR02": "registry-invalid", "KR03": "cluster-not-registered", "KR04": "override-argument",
    "KR05": "arguments-not-understood", "KR06": "authorization-unconfigured", "KR07": "authorization-record-invalid",
    "KR08": "request-outside-authorized-scope", "KR09": "identity-probe-not-authorized",
    "KR10": "kubeconfig-unreadable-or-unsupported", "KR11": "context-or-cluster-not-resolved",
    "KR12": "server-pin-mismatch", "KR13": "ca-pin-mismatch", "KR14": "tls-verification-disabled",
    "KR15": "identity-probe-failed", "KR16": "cluster-uid-mismatch", "KR17": "kubeconfig-changed-during-run",
    "KR18": "request-timed-out", "KR19": "kubectl-not-found", "KR20": "output-over-bound",
    "KR21": "stopped-by-signal", "KR22": "settlement-or-capture-not-proven", "KR23": "credential-helper-refused",
    "KR25": "custody-module-not-pinned", "KR26": "custody-unsupported-on-this-platform",
}


class Refused(Exception):
    def __init__(self, code, detail, exit_code=EXIT_REFUSED):
        super().__init__(code)
        self.code, self.detail, self.exit_code = code, detail, exit_code


# ---- 1. arguments --------------------------------------------------------------------------------
OVERRIDE_FLAGS = ("--kubeconfig", "--context", "--server", "-s", "--cluster", "--user", "--token", "--username",
                  "--password", "--as", "--as-group", "--as-uid", "--certificate-authority",
                  "--client-certificate", "--client-key", "--tls-server-name", "--insecure-skip-tls-verify",
                  "--kuberc")
VALUE_FLAGS = {"-o", "--output", "-l", "--selector", "-f", "--filename", "-c", "--container", "--field-selector",
               "--template", "--since", "--tail", "--sort-by", "-L", "--label-columns", "--chunk-size", "--timeout",
               "--for", "--request-timeout", "--since-time", "--limit-bytes", "-p", "--patch", "--type",
               "--replicas", "--revision", "--to-revision", "--grace-period", "-k", "--kustomize", "--subresource",
               "-v", "--v"}
NAMESPACE_FLAGS = ("-n", "--namespace")
ALL_NS_FLAGS = ("-A", "--all-namespaces")
# verb -> how to find its resources: an index into the positionals, or a fixed resource name.
VERBS = {
    "get": 1, "describe": 1, "delete": 1, "edit": None, "patch": 1, "label": 1, "annotate": 1, "scale": 1,
    "wait": 1, "apply": "<files>", "create": "<files>", "replace": "<files>", "diff": "<files>",
    "rollout": 2, "top": 1, "logs": "pods", "exec": "pods", "cp": "pods", "attach": "pods",
    "port-forward": "pods", "events": "events", "auth": "selfsubjectaccessreviews",
    "api-resources": "<discovery>", "api-versions": "<discovery>", "explain": "<discovery>",
    "version": "<discovery>", "cluster-info": "<discovery>",
}


def is_override(arg):
    return any(arg == f or arg.startswith(f + "=") for f in OVERRIDE_FLAGS)


def parse_request(args, default_namespace):
    """{"verb", "resources", "namespace"} for a kubectl argument list, or Refused."""
    if any(is_override(a) for a in args):
        raise Refused("KR04", "an argument selects or changes the cluster, identity or TLS; kube-run supplies "
                              "the kubeconfig and context from the registry")
    pos, namespaces, all_ns, unknown_at = [], [], False, None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        if a in NAMESPACE_FLAGS:
            if i + 1 >= len(args):
                raise Refused("KR05", "a namespace flag has no value")
            namespaces.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--namespace="):
            namespaces.append(a.partition("=")[2])
        elif a.startswith("-n") and a != "-n" and not a.startswith("--"):
            raise Refused("KR05", "an attached short namespace flag is not accepted; use -n <namespace>")
        elif a in ALL_NS_FLAGS or a in ("--all-namespaces=true",):
            all_ns = True
        elif a in VALUE_FLAGS:
            i += 1
        elif a.startswith("--") and "=" in a:
            pass
        elif a.startswith("-") and a != "-":
            if unknown_at is None:
                unknown_at = len(pos)
        else:
            pos.append(a)
        i += 1
    if not pos:
        raise Refused("KR05", "no kubectl verb")
    verb = pos[0]
    if verb not in VERBS:
        raise Refused("KR05", "the verb is not one kube-run supports (plugins and unknown verbs are refused)")
    if unknown_at == 0:
        raise Refused("KR05", "an unknown flag comes before the verb")
    how = VERBS[verb]
    if how is None:
        raise Refused("KR05", "interactive verbs are not supported")
    if isinstance(how, int):
        if len(pos) <= how or (unknown_at is not None and unknown_at <= how):
            raise Refused("KR05", "the resource cannot be read from the arguments unambiguously")
        resources = []
        for part in pos[how].split(","):
            r = part.split("/", 1)[0].strip().lower()
            if not r:
                raise Refused("KR05", "an empty resource name")
            resources.append(r)
    else:
        resources = [how]
    if len(set(namespaces)) > 1:
        raise Refused("KR05", "more than one namespace is named")
    if all_ns and namespaces:
        raise Refused("KR05", "both a namespace and all namespaces are named")
    namespace = "*" if all_ns else (namespaces[0] if namespaces else default_namespace)
    if not namespace:
        raise Refused("KR05", "an empty namespace")
    return {"verb": verb, "resources": resources, "namespace": namespace}


# ---- 2. registry ---------------------------------------------------------------------------------
REQUIRED_ENTRY = ("kubeconfig", "context", "server", "ca_sha256", "uid")


def load_entry(registry_path, cluster_id):
    try:
        with open(registry_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        raise Refused("KR02", "the registry is missing or is not JSON")
    clusters = data.get("clusters") if isinstance(data, dict) else None
    if not isinstance(clusters, dict):
        raise Refused("KR02", "the registry has no clusters object")
    if not CLUSTER_ID.match(cluster_id) or cluster_id not in clusters:
        raise Refused("KR03", "the cluster id is not in the registry")
    e = clusters[cluster_id]
    if not isinstance(e, dict) or any(not isinstance(e.get(k), str) or not e.get(k) for k in REQUIRED_ENTRY):
        raise Refused("KR02", "the registry entry lacks one of " + ", ".join(REQUIRED_ENTRY))
    if not os.path.isabs(e["kubeconfig"]) or not re.fullmatch(r"[0-9a-f]{64}", e["ca_sha256"]):
        raise Refused("KR02", "the registry entry's kubeconfig is not absolute or its ca_sha256 is not hex")
    if "kubectl" in e and (not isinstance(e["kubectl"], str) or not os.path.isabs(e["kubectl"])):
        raise Refused("KR02", "the registry entry's kubectl is not an absolute path")
    return e


# ---- 3. authorization interface ------------------------------------------------------------------
def _parse_time(s):
    if not isinstance(s, str) or not s.endswith("Z"):
        raise ValueError("not a UTC time")
    return _dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)


RECORD_FIELDS = {"ticket": str, "cluster_id": str, "verbs": list, "resources": list, "namespaces": list,
                 "allow_identity_probe": bool, "not_after": str, "authorized_by": str}


def _task_record(entry, cluster_id, record_path, request, probe, now):
    """Policy "task-record": a task authorization record must cover the request and the probe."""
    if not record_path:
        raise Refused("KR07", "this cluster's policy needs --authorization <record>")
    try:
        with open(record_path, encoding="utf-8") as f:
            rec = json.load(f)
        if not isinstance(rec, dict):
            raise ValueError
        for k, t in RECORD_FIELDS.items():
            if not isinstance(rec.get(k), t) or (t is str and not rec[k]):
                raise ValueError
        for k in ("verbs", "resources", "namespaces"):
            if not rec[k] or not all(isinstance(x, str) and x for x in rec[k]):
                raise ValueError
        not_after = _parse_time(rec["not_after"])
    except (OSError, ValueError):
        raise Refused("KR07", "the authorization record is missing, unreadable or lacks a required field")
    if rec["cluster_id"] != cluster_id:
        raise Refused("KR07", "the authorization record is for another cluster")
    if now >= not_after:
        raise Refused("KR07", "the authorization record has expired")
    if not rec["allow_identity_probe"]:
        raise Refused("KR09", "the record does not authorize the kube-system identity read that must precede "
                              "the request")

    def covers(allowed, value):
        return "*" in allowed or value in allowed

    if not covers(rec["verbs"], request["verb"]):
        raise Refused("KR08", "the verb is outside the authorized scope")
    if not all(covers(rec["resources"], r) for r in request["resources"]):
        raise Refused("KR08", "a resource is outside the authorized scope")
    if not covers(rec["namespaces"], request["namespace"]):
        raise Refused("KR08", "the namespace is outside the authorized scope")


POLICIES = {"task-record": _task_record}


def configured_policy(entry):
    """The entry's policy function. Refuses, before any file but the registry is read, when none is set."""
    auth = entry.get("authorization")
    policy = auth.get("policy") if isinstance(auth, dict) else None
    if policy not in POLICIES:
        raise Refused("KR06", "the registry entry has no implemented authorization policy configured, so every "
                              "call to it is refused")
    return POLICIES[policy]


def authorize(entry, cluster_id, record_path, request, now):
    """The authorization interface. Deployment chooses the policy per registry entry; none is the default."""
    probe = {"verb": "get", "resources": ["namespaces"], "namespace": None}
    configured_policy(entry)(entry, cluster_id, record_path, request, probe, now)


# ---- 4. kubeconfig as inert data -----------------------------------------------------------------
class Unsupported(Exception):
    pass


SCALAR_REFUSED = tuple("&*!|>{[%@`")


def _scalar(text):
    t = text.strip()
    if not t:
        return ""
    if t[0] == "'":
        if len(t) < 2 or t[-1] != "'":
            raise Unsupported("single-quoted scalar")
        return t[1:-1].replace("''", "'")
    if t[0] == '"':
        if len(t) < 2 or t[-1] != '"' or re.search(r'(?<!\\)(?:\\\\)*"', t[1:-1]):
            raise Unsupported("double-quoted scalar")
        body = t[1:-1]
        if re.search(r"\\[^\\\"/nt]", body):
            raise Unsupported("escape")
        return body.replace("\\\\", "\0").replace('\\"', '"').replace("\\/", "/").replace("\\n", "\n") \
            .replace("\\t", "\t").replace("\0", "\\")
    if t.startswith(SCALAR_REFUSED) or t in ("-", "?", ":"):
        raise Unsupported("anchor, alias, tag, block scalar or flow collection")
    m = re.search(r"\s#", t)
    if m:
        t = t[:m.start()].rstrip()
    if ": " in t or t.endswith(":"):
        raise Unsupported("nested mapping in a scalar")
    return t


def _key_value(text):
    m = re.match(r"^([A-Za-z0-9_.\-]+):(?:\s+(.*))?$", text)
    if not m:
        raise Unsupported("not a key")
    return m.group(1), (m.group(2) or "")


def _block(lines, i, indent):
    """Parse a block mapping or sequence at exactly `indent`. Returns (value, next index)."""
    if i >= len(lines) or lines[i][0] != indent:
        raise Unsupported("indentation")
    if lines[i][1] == "-" or lines[i][1].startswith("- "):
        seq = []
        while i < len(lines) and lines[i][0] == indent and (lines[i][1] == "-" or lines[i][1].startswith("- ")):
            rest = lines[i][1][1:].lstrip(" ")
            if not rest:
                value, i = _block(lines, i + 1, lines[i + 1][0] if i + 1 < len(lines) else -1)
                seq.append(value)
                continue
            inner = indent + (len(lines[i][1]) - len(rest))
            if re.match(r"^[A-Za-z0-9_.\-]+:(\s|$)", rest):
                sub = [(inner, rest)] + []
                j = i + 1
                while j < len(lines) and lines[j][0] > indent:
                    sub.append(lines[j])
                    j += 1
                value, k = _block(sub, 0, inner)
                if k != len(sub):
                    raise Unsupported("indentation in a sequence item")
                seq.append(value)
                i = j
            else:
                seq.append(_scalar(rest))
                i += 1
        if i < len(lines) and lines[i][0] > indent:
            raise Unsupported("indentation after a sequence")
        return seq, i
    mapping = {}
    while i < len(lines) and lines[i][0] == indent:
        if lines[i][1].startswith("-"):
            raise Unsupported("a sequence item inside a mapping")
        key, raw = _key_value(lines[i][1])
        if key in mapping:
            raise Unsupported("duplicate key")
        i += 1
        if raw.strip() and not raw.strip().startswith("#"):
            mapping[key] = _scalar(raw)
        elif i < len(lines) and lines[i][0] > indent:
            mapping[key], i = _block(lines, i, lines[i][0])
        elif i < len(lines) and lines[i][0] == indent and (lines[i][1] == "-" or lines[i][1].startswith("- ")):
            mapping[key], i = _block(lines, i, indent)
        else:
            mapping[key] = None
    if i < len(lines) and lines[i][0] > indent:
        raise Unsupported("indentation after a mapping")
    return mapping, i


TOP_KEY = re.compile(r"^([A-Za-z0-9_.\-]+):(?:[ \t]+(\S.*))?$")


def read_sections(data):
    """{"clusters": [...], "contexts": [...]} from kubeconfig bytes. Other sections are skipped unparsed."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Unsupported("not UTF-8")
    raw = text.split("\n")
    sections, current, seen, first = {}, None, set(), True
    for n, line in enumerate(raw):
        line = line.rstrip("\r")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line[0] not in " -":  # a column-0 line that is not a sequence item: a top-level key or a marker
            if stripped == "---" and first:
                first = False
                continue
            first = False
            m = TOP_KEY.match(line)
            if not m:
                raise Unsupported("a top-level line that is not a key (JSON, flow style, a document marker)")
            key = m.group(1)
            if key in seen:
                raise Unsupported("duplicate top-level key")
            seen.add(key)
            if key in ("clusters", "contexts"):
                if m.group(2) and m.group(2).strip() != "[]":
                    raise Unsupported("an inline value for a parsed section")
                current = key
                sections[key] = []
            else:
                current = None  # stepped over: its lines are never interpreted
            continue
        first = False
        if current is None:
            continue
        if "\t" in line[:len(line) - len(line.lstrip())]:
            raise Unsupported("a tab in indentation")
        sections[current].append((len(line) - len(line.lstrip(" ")), line.strip()))
    out = {}
    for key in ("clusters", "contexts"):
        lines = sections.get(key)
        if not lines:
            out[key] = []
            continue
        value, i = _block(lines, 0, lines[0][0])
        if i != len(lines) or not isinstance(value, list):
            raise Unsupported(f"the {key} section is not a sequence")
        out[key] = value
    return out


def _one(items, name, field):
    found = [x for x in items if isinstance(x, dict) and x.get("name") == name]
    if len(found) != 1 or not isinstance(found[0].get(field), dict):
        raise Refused("KR11", f"the pinned {field} is missing or defined more than once in the kubeconfig")
    return found[0][field]


def check_pins(entry, data, kubeconfig_dir):
    """Raises Refused unless the pinned context resolves to the pinned server and CA. Returns the context's
    namespace (or None). Uses only the clusters and contexts sections."""
    try:
        sec = read_sections(data)
    except Unsupported:
        raise Refused("KR10", "the kubeconfig uses syntax kube-run's restricted reader does not accept")
    ctx = _one(sec["contexts"], entry["context"], "context")
    cluster_name = ctx.get("cluster")
    if not isinstance(cluster_name, str) or not cluster_name:
        raise Refused("KR11", "the pinned context names no cluster")
    cluster = _one(sec["clusters"], cluster_name, "cluster")
    if str(cluster.get("insecure-skip-tls-verify", "")).lower() in ("true", "yes", "on", "1"):
        raise Refused("KR14", "the pinned cluster disables TLS verification")
    if cluster.get("server") != entry["server"]:
        raise Refused("KR12", "the pinned context's server is not the registry's server")
    data_field, path_field = cluster.get("certificate-authority-data"), cluster.get("certificate-authority")
    if bool(data_field) == bool(path_field):
        raise Refused("KR13", "the pinned cluster must carry exactly one CA (data or file)")
    try:
        if data_field:
            ca = base64.b64decode("".join(str(data_field).split()), validate=True)
        else:
            p = os.path.join(kubeconfig_dir, os.path.expanduser(str(path_field)))
            with open(p, "rb") as f:
                ca = f.read()
    except (OSError, binascii.Error, ValueError):
        raise Refused("KR13", "the pinned cluster's CA cannot be read")
    if hashlib.sha256(ca).hexdigest() != entry["ca_sha256"]:
        raise Refused("KR13", "the pinned cluster's CA is not the registry's CA")
    ns = ctx.get("namespace")
    user = ctx.get("user")
    return (ns if isinstance(ns, str) and ns else None), (user if isinstance(user, str) and user else None)


# ---- 5, 6. bounded execution -----------------------------------------------------------------
class Timeout(Exception):
    pass


class OutputOverBound(Exception):
    pass


class Stopped(BaseException):
    """A signal asked kube-run to stop. BaseException, so no `except Exception` on the way swallows it."""


class Unsettled(Exception):
    """B5 could not prove settlement or a complete capture (its rc 125)."""

    def __init__(self, cause):
        super().__init__(cause)
        self.cause = cause


class PlatformUnsupported(Exception):
    """B5 refused before creating any child, because this platform lacks a capability it needs (its rc 125 with
    "refused before any child")."""

    def __init__(self, cause):
        super().__init__(cause)
        self.cause = cause


# ---- the reviewed B5 host custody, loaded from its pinned copy ---------------------------------
B5_FILE = "b5_custody.py"
B5_SHA256 = "b373e5a802132c698d5734f92f686f0a07cd386ebd5c02aa21b1f1de8f8e1b8e"
# B5's own failure reasons. Only a last line that matches one of these is shown; anything else is withheld,
# because the rest of stderr is kubectl's and may carry values.
B5_WHY = re.compile(r"^(?:pid \d+ pgid \d+: [^\n]*|capture truncated: [^\n]*|output over the \d+-byte cap"
                    r"|spawn failed: \w+|refused before any child: [^\n]*|not run: bound -?\d+)"
                    r"(?:; harness close failure: [^\n]*)?$")


def load_b5(directory=None):
    """The B5 module, executed from the exact bytes whose sha256 was checked (no re-read between the check and
    the load). Refused (KR25) when the copy is missing or is not the pinned one."""
    path = os.path.join(directory or os.path.dirname(os.path.realpath(__file__)), B5_FILE)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        raise Refused("KR25", "the pinned custody module is missing")
    if hashlib.sha256(data).hexdigest() != B5_SHA256:
        raise Refused("KR25", "the custody module is not the pinned copy of the reviewed B5 section")
    module = types.ModuleType("b5_custody")
    module.__file__ = path
    exec(compile(data, path, "exec"), module.__dict__)  # the verified bytes, nothing re-read
    return module


def b5_why(err):
    last = err.rstrip("\n").rsplit("\n", 1)[-1] if err else ""
    return last if B5_WHY.match(last) else "reason withheld"


class B5Transport:
    """kube-run's transport: B5's bounded_run, unchanged. Its rc 124 is a timeout and its rc 125 an unproven
    settlement, truncated capture, output over the cap or failed spawn; anything else is kubectl's own status.
    LIMIT, B5's own and stated: a descendant that calls setsid() leaves the group and is neither signalled nor
    seen; while it holds a pipe it shows as a truncated capture (refused). kube-run therefore refuses kubeconfig
    users that run a credential helper (KR23), the one kind of descendant kubectl is known to start. Ambiguity:
    a kubectl that itself exits 124 or 125 reads as B5's 124 or 125, which fails closed."""

    def __init__(self, b5=None):
        self.b5 = b5 or load_b5()

    def run(self, argv, env, timeout):
        rc, out, err = self.b5.bounded_run(list(argv), int(timeout), dict(env))
        if rc == 124:
            raise Timeout()
        if rc == 125:
            why = b5_why(err)
            if why.startswith("output over the"):
                raise OutputOverBound()
            if why.startswith("refused before any child"):
                raise PlatformUnsupported(why)
            raise Unsettled(why)
        return rc, out.encode("utf-8"), err.encode("utf-8")


# ---- credential helpers: refused, because B5 cannot follow a descendant that leaves its group -------------
STATIC_USER_KEYS = {"token", "tokenFile", "client-certificate", "client-certificate-data", "client-key",
                    "client-key-data", "username", "password"}


def user_keys(data, user_name):
    """The KEY NAMES directly under users[name == user_name].user. Values are never decoded, except each user
    item's `name` (to find the one the context names). Unsupported layout raises Unsupported."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Unsupported("not UTF-8")
    in_users, base, items = False, None, []
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if line[0] not in " -":
            m = TOP_KEY.match(line)
            in_users = bool(m) and m.group(1) == "users"
            if in_users and (m.group(2) or "").strip() not in ("", "[]"):
                raise Unsupported("an inline users value")
            continue
        if not in_users:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if s.startswith("- ") and (base is None or indent == base):
            base = indent
            items.append([(indent + 2, s[2:].lstrip(" "))])
        elif items and indent > base:
            items[-1].append((indent, s))
        else:
            raise Unsupported("a users line outside an item")
    for item in items:
        top = base + 2
        name, user_at, inline = None, None, None
        for i, (ind, t) in enumerate(item):
            if ind != top:
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+):(?:\s+(.*))?$", t)
            if not m:
                raise Unsupported("a users item line that is not a key")
            if m.group(1) == "name":
                name = _scalar(m.group(2) or "")
            elif m.group(1) == "user":
                user_at, inline = i, (m.group(2) or "").strip()
        if name != user_name:
            continue
        if user_at is None:
            raise Unsupported("the user item has no user mapping")
        if inline:
            if inline == "{}":
                return set()
            raise Unsupported("an inline user mapping")
        child = []
        for ind, t in item[user_at + 1:]:
            if ind <= top:
                break
            child.append((ind, t))
        if not child:
            return set()
        level, keys = child[0][0], set()
        for ind, t in child:
            if ind == level:
                m = re.match(r"^([A-Za-z0-9_.\-]+):", t)
                if not m:
                    raise Unsupported("a user line that is not a key")
                keys.add(m.group(1))
        return keys
    raise Unsupported("the context's user is not in the users section")


def _call(transport, argv, env, timeout, step):
    """One bounded transport call. Timeout is left to the caller; every other outcome is a fixed refusal."""
    try:
        return transport.run(argv, env, timeout)
    except PlatformUnsupported as p:
        raise Refused("KR26", f"{step}: B5 custody is not available on this platform ({p.cause}); no process was "
                              "started")
    except Unsettled as u:
        raise Refused("KR22", f"{step}: B5 could not prove settlement or a complete capture ({u.cause}); "
                              "nothing further was run", EXIT_UNSETTLED)
    except OutputOverBound:
        raise Refused("KR20", f"{step} exceeded the output bound and was killed")
    except OSError:
        raise Refused("KR19", f"{step}: kubectl could not be started")
    except Stopped:
        raise Refused("KR21", f"{step} was stopped by a signal. B5 settles its group in a finally block, but that "
                              "result is not reported on this path, so treat settlement as UNKNOWN; nothing "
                              "further was run", EXIT_STOPPED)


def child_env(environ):
    env = {k: environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "LOGNAME") if k in environ}
    env["KUBERC"] = "off"
    return env


def pinned(kubectl, entry):
    return [kubectl, "--kubeconfig", entry["kubeconfig"], "--context", entry["context"]]


def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        raise Refused("KR10", "the pinned kubeconfig cannot be read")


def parse_cli(argv):
    record, timeout, i = None, DEFAULT_TIMEOUT_S, 0
    while i < len(argv) and argv[i].startswith("--") and argv[i] != "--":
        a = argv[i]
        if a == "--authorization" and i + 1 < len(argv):
            record, i = argv[i + 1], i + 2
        elif a == "--timeout" and i + 1 < len(argv) and argv[i + 1].isdigit():
            timeout, i = int(argv[i + 1]), i + 2
        else:
            raise Refused("KR01", "usage: kube-run [--authorization FILE] [--timeout SECONDS] <cluster-id> -- "
                                  "<kubectl arguments>")
    if not 1 <= timeout <= MAX_TIMEOUT_S:
        raise Refused("KR01", f"--timeout must be 1..{MAX_TIMEOUT_S}")
    if i + 1 >= len(argv) or argv[i + 1] != "--" or i + 2 >= len(argv):
        raise Refused("KR01", "usage: kube-run [--authorization FILE] [--timeout SECONDS] <cluster-id> -- "
                              "<kubectl arguments>")
    return record, timeout, argv[i], argv[i + 2:]


def run(argv, registry_path, transport, now, environ, stdout, stderr):
    record, timeout, cluster_id, kargs = parse_cli(argv)
    if any(is_override(a) for a in kargs):  # before any file is read
        parse_request(kargs, "default")
    entry = load_entry(registry_path, cluster_id)
    configured_policy(entry)  # an unconfigured entry is refused before its kubeconfig is opened
    data = read_bytes(entry["kubeconfig"])
    digest = hashlib.sha256(data).digest()
    # Namespace default comes from the pinned context, so the pins are checked before scope.
    ctx_ns, ctx_user = check_pins(entry, data, os.path.dirname(entry["kubeconfig"]))
    if ctx_user is None:
        raise Refused("KR11", "the pinned context names no user")
    try:
        keys = user_keys(data, ctx_user)
    except Unsupported:
        raise Refused("KR10", "the pinned user's entry uses a layout kube-run's restricted reader does not accept")
    if keys - STATIC_USER_KEYS:
        raise Refused("KR23", "the pinned user runs a credential helper or uses keys kube-run does not support "
                              "(exec, auth-provider, impersonation); B5 cannot follow a helper that leaves its "
                              "process group, so kube-run refuses it")
    request = parse_request(kargs, ctx_ns or "default")
    authorize(entry, cluster_id, record, request, now)
    kubectl = entry.get("kubectl") or shutil.which("kubectl", path=environ.get("PATH"))
    if not kubectl:
        raise Refused("KR19", "kubectl is not on PATH and the registry entry pins none")
    env = child_env(environ)
    probe = pinned(kubectl, entry) + ["--request-timeout=" + PROBE_REQUEST_TIMEOUT, "get", "namespace",
                                      "kube-system", "-o", "jsonpath={.metadata.uid}"]
    try:
        rc, out, _ = _call(transport, probe, env, PROBE_TIMEOUT_S, "the identity probe")
    except Timeout:
        raise Refused("KR15", "the identity probe timed out; the request was not made", EXIT_PROBE)
    if rc != 0 or not out.strip():
        raise Refused("KR15", "the identity probe failed or returned nothing; the request was not made",
                      EXIT_PROBE)
    if out.decode("utf-8", "replace").strip() != entry["uid"]:
        raise Refused("KR16", "the cluster behind the pinned context is not the registered cluster; the request "
                              "was not made")
    if hashlib.sha256(read_bytes(entry["kubeconfig"])).digest() != digest:
        raise Refused("KR17", "the kubeconfig changed after its pins were checked; the request was not made")
    try:
        rc, out, err = _call(transport, pinned(kubectl, entry) + kargs, env, timeout, "the request")
    except Timeout:
        raise Refused("KR18", "the request exceeded --timeout and was killed", EXIT_TIMEOUT)
    stdout.write(out)
    stderr.write(err)
    stdout.flush()
    stderr.flush()
    print(f"kube-run: cluster={cluster_id} verb={request['verb']} identity=verified rc={rc}",
          file=_text(stderr))
    return rc


def _text(stream):
    class W:
        def write(self, s):
            stream.write(s.encode("utf-8"))

        def flush(self):
            stream.flush()
    return W()


def _on_signal(signum, _frame):
    raise Stopped(signal.Signals(signum).name)


STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def main(argv, registry_path=REGISTRY_PATH, transport=None, now=None, environ=None, stdout=None, stderr=None):
    stdout = stdout or sys.stdout.buffer
    stderr = stderr or sys.stderr.buffer
    previous = {}

    def refuse(code, detail, exit_code):
        msg = (f"kube-run (TXE-8039): refused [{code} {CODES[code]}]: {detail}. Values are withheld. "
               "Report this verbatim to your coordinator; do not work around it.\n")
        stderr.write(msg.encode("utf-8"))
        stderr.flush()
        return exit_code

    try:
        # A stop signal raises Stopped wherever it lands, so B5's finally settles a running group (an outer
        # timeout such as gtimeout sends SIGTERM first).
        for s in STOP_SIGNALS:
            try:
                previous[s] = signal.signal(s, _on_signal)
            except ValueError:  # not the main thread
                pass
        return run(argv, registry_path, transport or B5Transport(),
                   now or _dt.datetime.now(_dt.timezone.utc), os.environ if environ is None else environ,
                   stdout, stderr)
    except Refused as r:
        return refuse(r.code, r.detail, r.exit_code)
    except Stopped:
        return refuse("KR21", "stopped by a signal outside a transport call; nothing further was run", EXIT_STOPPED)
    finally:
        for s, h in previous.items():
            signal.signal(s, h)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
