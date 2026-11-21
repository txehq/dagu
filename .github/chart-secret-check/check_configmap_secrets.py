#!/usr/bin/env python3
"""Fail when a credential reaches a ConfigMap in rendered Helm output (TXE-8035).

A ConfigMap is not a Secret: whoever may read ConfigMaps in the namespace reads
every value in it. This checker reads `helm template` output and fails when any
ConfigMap carries a credential. It also checks the chart's values.yaml so a new
literal credential input cannot be added without review.

Subcommands:
  derive  --config-dir DIR             print the credential keys derived from Dagu
  check   --config-dir DIR MANIFEST    check every ConfigMap in MANIFEST
  values  VALUES_YAML                  check the chart's values.yaml inputs

Exit codes: 0 clean, 1 a finding, 2 incomplete input (a derivation or manifest
that could not be read completely). A derivation that finds nothing, or meets a
form it does not recognise, is exit 2, never a clean pass.

What is derived from Dagu's source (internal/cmn/config), so a new credential
key is covered with no edit here:
  * every `envBindings` entry marked `secret: true` (loader.go): its YAML key and
    its DAGU_ environment name;
  * every key passed to `newSecretFile(...)` in `loadSecretFiles` (loader.go),
    including the `remote_nodes[%d]` keys built with fmt.Sprintf;
  * every name in `directCredentialEnv` (credential_env.go).
A key that is a file path (isPath, or a name ending in _file) is recorded but
not denied: a path to a mounted secret file is not the credential.

Parser limits, by design fail-closed. It reads Go source as text with a small
tokenizer, not a Go parser. It accepts only these forms and exits 2 on anything
else:
  * `var envBindings = []envBinding{ {field: value, ...}, ... }` with fields
    key, env, isPath, requires, secret; key and env are string literals or
    identifiers bound by a string `const` in the package (a literal, or a +
    concatenation of literals and such constants); secret and isPath are
    the literals true or false;
  * no other assignment or append to envBindings in the package;
  * `newSecretFile(<string literal> | fmt.Sprintf(<literal using %d>, ...), ...)`;
  * `var directCredentialEnv = []string{ <string literals> }`.
A credential the app reads by some other route is not derived; the name and
value rules below are the second line for those.

Rules for each ConfigMap (data values, and binaryData values after base64
decoding; each value is also parsed as YAML, and string scalars that hold YAML
are parsed again, up to a fixed depth):
  1. a non-empty value at a derived credential key (matched as a path suffix,
     case-insensitively, as Dagu's config reader matches keys), or under a key
     that is a derived DAGU_ credential environment name;
  2. a non-empty value under a key whose name says credential (secret, password,
     passphrase, token, api_key, private_key, credential, client_secret, ...),
     except the explicit reference keys below, whose value must be a Kubernetes
     object name; a <credential>_file key must hold an absolute path;
  3. a value shaped like a credential (PEM private key, GitHub or AWS token);
  4. any SECRET-VALUE canary (FAKE-SECRET-VALUE-...) planted by the fixtures.
     REFERENCE canaries (fake-ref-...) are names of Secrets and are allowed.
  5. NAME=value lines whose name says credential, or is a derived env name.
Findings name the ConfigMap, the data key and the path, never the value.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import pathlib
import re
import sys
from dataclasses import dataclass, field

SECRET_VALUE_CANARY = "FAKE-SECRET-VALUE-"
REFERENCE_CANARY = "fake-ref-"
APP_ENV_PREFIX = "DAGU_"
NESTED_YAML_DEPTH = 4

ENV_BINDING_FIELDS = {"key", "env", "isPath", "requires", "secret"}

# Rule 2: a key whose normalised name ends in one of these words says credential.
CREDENTIAL_NAME = re.compile(
    r"(^|_)(secret|secrets|password|passwd|passphrase|token|tokens|api_key|apikey"
    r"|private_key|credential|credentials|auth_key|access_key|secret_key|client_secret"
    r"|hub_key|license_key|encryption_key)$"
)
# Explicit reference keys: their value names a Kubernetes object and is not the
# credential. Nothing else is exempt. secret_key is deliberately absent: in S3
# and similar configs it is the credential itself.
REFERENCE_KEYS = {"existing_secret", "secret_name"}
K8S_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
ABSOLUTE_PATH = re.compile(r"^/\S*$")

# Rule 3: value shapes.
VALUE_SHAPES = [
    ("PEM private key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}")),
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
]
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S.*)$")

# values.yaml: every credential-named leaf must be listed here with its kind.
# A listed path missing from values.yaml is also a finding, so this stays exact.
VALUES_ALLOWLIST = {
    "auth.basic.existingSecret": "reference",
    "auth.basic.passwordKey": "secret-key-name",
    "auth.builtin.token.existingSecret": "reference",
    "auth.builtin.token.secretKey": "secret-key-name",
    "auth.builtin.token.secret": "removed-must-be-empty",
    "auth.oidc.clientSecret.existingSecret": "reference",
    "auth.oidc.clientSecret.secretKey": "secret-key-name",
    "license.existingSecret": "reference",
    "license.secretKey": "secret-key-name",
    "ingress.tls.secretName": "reference",
}
SECRET_KEY_NAME = re.compile(r"^[-._a-zA-Z0-9]*$")


class Incomplete(Exception):
    """Input that could not be read completely: exit 2."""


# ---------------------------------------------------------------- Go source


def _skip_string(src: str, i: int) -> int:
    """Return the index after the string or rune literal starting at i."""
    quote = src[i]
    j = i + 1
    if quote == "`":
        end = src.find("`", j)
        if end < 0:
            raise Incomplete("unterminated raw string")
        return end + 1
    while j < len(src):
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == quote:
            return j + 1
        if c == "\n":
            break
        j += 1
    raise Incomplete("unterminated string literal")


def strip_comments(src: str) -> str:
    """Replace Go comments with spaces, keeping offsets and string literals."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c in "\"'`":
            j = _skip_string(src, i)
            out.append(src[i:j])
            i = j
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                raise Incomplete("unterminated block comment")
            out.append(re.sub(r"[^\n]", " ", src[i : j + 2]))
            i = j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def matching(src: str, i: int) -> int:
    """Index of the bracket closing the one at src[i] (comments stripped)."""
    pairs = {"{": "}", "(": ")", "[": "]"}
    stack = [pairs[src[i]]]
    j = i + 1
    while j < len(src):
        c = src[j]
        if c in "\"'`":
            j = _skip_string(src, j)
            continue
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")]}":
            if not stack or stack.pop() != c:
                raise Incomplete(f"unbalanced {c!r}")
            if not stack:
                return j
        j += 1
    raise Incomplete("unclosed bracket")


def split_top(src: str) -> list[str]:
    """Split on commas that are not inside brackets or strings."""
    parts, depth, start, j = [], 0, 0, 0
    while j < len(src):
        c = src[j]
        if c in "\"'`":
            j = _skip_string(src, j)
            continue
        if c in "{([":
            depth += 1
        elif c in "})]":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(src[start:j])
            start = j + 1
        j += 1
    parts.append(src[start:])
    return [p.strip() for p in parts if p.strip()]


GO_STRING = re.compile(r'^"((?:[^"\\\n]|\\.)*)"$')
GO_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def go_string(token: str) -> str | None:
    m = GO_STRING.match(token.strip())
    if not m:
        return None
    if "\\" in m.group(1):
        raise Incomplete(f"escaped string literal not supported: {token.strip()}")
    return m.group(1)


def _split_plus(expr: str) -> list[str] | None:
    """Split a constant expression on + outside string literals; None if empty."""
    parts, start, j = [], 0, 0
    while j < len(expr):
        if expr[j] in "\"'`":
            j = _skip_string(expr, j)
            continue
        if expr[j] == "+":
            parts.append(expr[start:j].strip())
            start = j + 1
        j += 1
    parts.append(expr[start:].strip())
    return None if any(not p for p in parts) else parts


def string_consts(sources: dict[str, str]) -> dict[str, str]:
    """String constants declared in the package, by name.

    A constant is a string literal, or a + concatenation of string literals and
    other string constants (license.fork_policy keys in loader.go). Anything
    else (iota, typed numbers, calls) is not recorded, so a binding that uses
    it fails to resolve and the derivation stops: fail closed.
    """
    exprs: dict[str, str] = {}
    ambiguous: set[str] = set()
    spec = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s+[A-Za-z_][A-Za-z0-9_.]*)?\s*=\s*(\S.*?)\s*$")

    def record(name: str, expr: str) -> None:
        # A name declared twice with different values (function-local
        # constants) resolves to nothing, so a binding using it stops.
        if name in exprs and exprs[name] != expr:
            ambiguous.add(name)
        exprs[name] = expr

    for text in sources.values():
        for m in re.finditer(r"\bconst\b", text):
            k = m.end()
            while k < len(text) and text[k] in " \t":
                k += 1
            if k < len(text) and text[k] == "(":
                block = text[k + 1 : matching(text, k)]
                for line in block.splitlines():
                    s = spec.match(line)
                    if s:
                        record(s.group(1), s.group(2))
            else:
                line_end = text.find("\n", k)
                s = spec.match(text[k : len(text) if line_end < 0 else line_end])
                if s:
                    record(s.group(1), s.group(2))

    consts: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for name, expr in exprs.items():
            if name in consts or name in ambiguous:
                continue
            try:
                parts = _split_plus(expr)
            except Incomplete:
                parts = None  # a literal that does not close on this line
            if parts is None:
                continue
            values = []
            for part in parts:
                try:
                    literal = go_string(part)
                except Incomplete:
                    break  # an escaped literal: left unresolved, so a binding using it stops the derivation
                if literal is not None:
                    values.append(literal)
                elif GO_IDENT.match(part) and part in consts:
                    values.append(consts[part])
                else:
                    break
            else:
                consts[name] = "".join(values)
                changed = True
    return consts


def load_sources(config_dir: pathlib.Path) -> dict[str, str]:
    files = sorted(p for p in config_dir.glob("*.go") if not p.name.endswith("_test.go"))
    if not files:
        raise Incomplete(f"no Go sources in {config_dir}")
    return {p.name: strip_comments(p.read_text(encoding="utf-8")) for p in files}


def composite_body(text: str, header: re.Pattern[str], what: str) -> str:
    m = header.search(text)
    if not m:
        raise Incomplete(f"{what} not found")
    if header.search(text, m.end()):
        raise Incomplete(f"{what} declared more than once")
    brace = m.end() - 1
    return text[brace + 1 : matching(text, brace)]


@dataclass
class Derived:
    keys: set[str] = field(default_factory=set)  # dotted, lowercase, [] for list items
    envs: set[str] = field(default_factory=set)  # upper-case, with DAGU_ prefix
    path_keys: set[str] = field(default_factory=set)
    secret_bindings: int = 0
    secret_files: int = 0
    direct_envs: int = 0


ENVBINDINGS_HEADER = re.compile(r"\bvar\s+envBindings\s*=\s*\[\]envBinding\s*\{")
DIRECT_ENV_HEADER = re.compile(r"\bvar\s+directCredentialEnv\s*=\s*\[\]string\s*\{")
LOAD_SECRET_FILES = re.compile(r"\bfunc\s*\(\s*\w+\s+\*ConfigLoader\s*\)\s*loadSecretFiles\s*\([^)]*\)\s*(?:error\s*)?\{")


def _resolve(token: str, consts: dict[str, str], what: str) -> str:
    value = go_string(token)
    if value is not None:
        return value
    if GO_IDENT.match(token) and token in consts:
        return consts[token]
    raise Incomplete(f"{what}: cannot resolve {token!r} to a string")


def _bool(token: str, what: str) -> bool:
    if token not in ("true", "false"):
        raise Incomplete(f"{what}: expected true or false, got {token!r}")
    return token == "true"


def derive(config_dir: pathlib.Path) -> Derived:
    sources = load_sources(config_dir)
    consts = string_consts(sources)
    d = Derived()

    loader = sources.get("loader.go")
    if loader is None:
        raise Incomplete("loader.go not found")

    # envBindings: every element must be a keyed composite literal.
    body = composite_body(loader, ENVBINDINGS_HEADER, "var envBindings = []envBinding{")
    for name, text in sources.items():
        rest = text
        if name == "loader.go":
            m = ENVBINDINGS_HEADER.search(text)
            assert m is not None  # composite_body found it above
            rest = text[: m.start()] + text[matching(text, m.end() - 1) + 1 :]
        if re.search(r"\benvBindings\s*(\[[^\]]*\]\s*)?=[^=]", rest):
            raise Incomplete(f"envBindings is assigned outside its declaration ({name})")
    elements = 0
    i = 0
    while i < len(body):
        c = body[i]
        if c.isspace() or c == ",":
            i += 1
            continue
        if c != "{":
            raise Incomplete(f"envBindings: unrecognised entry starting {body[i:i + 30]!r}")
        end = matching(body, i)
        elements += 1
        fields: dict[str, str] = {}
        for part in split_top(body[i + 1 : end]):
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)$", part, re.S)
            if not m:
                raise Incomplete(f"envBindings: unkeyed field {part!r}")
            fname, value = m.group(1), m.group(2).strip()
            if fname not in ENV_BINDING_FIELDS:
                raise Incomplete(f"envBindings: unknown field {fname!r}")
            fields[fname] = value
        if "key" not in fields or "env" not in fields:
            raise Incomplete("envBindings: an entry has no key or env")
        is_secret = _bool(fields["secret"], "envBindings secret") if "secret" in fields else False
        is_path = _bool(fields["isPath"], "envBindings isPath") if "isPath" in fields else False
        key = _resolve(fields["key"], consts, "envBindings key")
        env = _resolve(fields["env"], consts, "envBindings env")
        if is_secret:
            d.secret_bindings += 1
            if is_path or key.endswith("_file") or env.endswith("_FILE"):
                d.path_keys.add(key.lower())
            else:
                d.keys.add(key.lower())
                d.envs.add(APP_ENV_PREFIX + env.upper())
        i = end + 1
    if elements == 0:
        raise Incomplete("envBindings has no entries")
    if d.secret_bindings == 0:
        raise Incomplete("envBindings has no entry marked secret: true")
    if len(re.findall(r"\bsecret\s*:\s*true\b", body)) != d.secret_bindings:
        raise Incomplete("envBindings: secret: true count does not match the entries read")

    # loadSecretFiles: every newSecretFile call.
    fbody = composite_body(loader, LOAD_SECRET_FILES, "func (l *ConfigLoader) loadSecretFiles")
    calls = [m.end() - 1 for m in re.finditer(r"\bnewSecretFile\s*\(", fbody)]
    if not calls:
        raise Incomplete("loadSecretFiles has no newSecretFile call")
    for start in calls:
        args = split_top(fbody[start + 1 : matching(fbody, start)])
        if not args:
            raise Incomplete("newSecretFile call without arguments")
        first = args[0]
        key = go_string(first)
        if key is None:
            m = re.match(r"^fmt\.Sprintf\s*\((.*)\)$", first, re.S)
            if not m:
                raise Incomplete(f"newSecretFile: unrecognised key expression {first!r}")
            fmt_args = split_top(m.group(1))
            fmt_key = go_string(fmt_args[0]) if fmt_args else None
            if fmt_key is None or "%" in fmt_key.replace("[%d]", ""):
                raise Incomplete(f"newSecretFile: unrecognised format {first!r}")
            key = fmt_key.replace("[%d]", "[]")
        d.secret_files += 1
        if key.endswith("_file"):
            d.path_keys.add(key.lower())
        else:
            d.keys.add(key.lower())

    # directCredentialEnv: string literals only.
    cred = sources.get("credential_env.go")
    if cred is None:
        raise Incomplete("credential_env.go not found")
    dbody = composite_body(cred, DIRECT_ENV_HEADER, "var directCredentialEnv = []string{")
    for item in split_top(dbody):
        value = go_string(item)
        if value is None:
            raise Incomplete(f"directCredentialEnv: unrecognised entry {item!r}")
        d.direct_envs += 1
        d.envs.add(APP_ENV_PREFIX + value.upper())
    if d.direct_envs == 0:
        raise Incomplete("directCredentialEnv has no entries")

    if not d.keys or not d.envs:
        raise Incomplete("derived no credential keys")
    return d


# ---------------------------------------------------------------- manifests


def normalise_name(name: str) -> str:
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name))
    return name.replace("-", "_").replace(".", "_").lower()


def _path_text(path: list[str]) -> str:
    out = ""
    for seg in path:
        out += seg if seg == "[]" else (("." if out else "") + seg)
    return out or "<root>"


def _segments(dotted: str) -> list[str]:
    segs: list[str] = []
    for part in dotted.split("."):
        if part.endswith("[]"):
            segs.extend([part[:-2], "[]"])
        else:
            segs.append(part)
    return segs


def _non_empty(value: object) -> bool:
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (dict, list)):
        return False
    return str(value).strip() != ""


@dataclass
class Checker:
    derived: Derived
    findings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.deny_paths = [_segments(k) for k in sorted(self.derived.keys)]

    def report(self, where: str, path: list[str], rule: str, value: object = None) -> None:
        size = f", {len(str(value))} chars" if value is not None else ""
        self.findings.append(f"{where} {_path_text(path)}: {rule} (value withheld{size})")

    def scan_text(self, where: str, text: str) -> None:
        if SECRET_VALUE_CANARY in text:
            self.report(where, [], "holds a planted secret-value canary")
        for label, pattern in VALUE_SHAPES:
            if pattern.search(text):
                self.report(where, [], f"holds a value shaped like a {label}")
        for n, line in enumerate(text.splitlines(), 1):
            m = ENV_LINE.match(line)
            if not m:
                continue
            name, value = m.group(1), m.group(2)
            if name.upper() in self.derived.envs or CREDENTIAL_NAME.search(normalise_name(name)):
                self.report(where, [f"line {n}", name], "assigns a credential variable", value)

    def check_leaf(self, where: str, path: list[str], key: str, value: object) -> None:
        if not _non_empty(value):
            return
        lowered = [p.lower() for p in path]
        for deny in self.deny_paths:
            if len(lowered) >= len(deny) and lowered[-len(deny) :] == deny:
                self.report(where, path, "is a Dagu credential key", value)
                return
        if key.upper() in self.derived.envs:
            self.report(where, path, "is a Dagu credential environment variable", value)
            return
        name = normalise_name(key)
        if name in REFERENCE_KEYS:
            if not K8S_NAME.match(str(value)) or len(str(value)) > 253:
                self.report(where, path, "is a reference key whose value is not a Kubernetes object name", value)
            return
        if name.endswith("_file") and CREDENTIAL_NAME.search(name[: -len("_file")]):
            if not ABSOLUTE_PATH.match(str(value)):
                self.report(where, path, "is a credential file key whose value is not an absolute path", value)
            return
        if CREDENTIAL_NAME.search(name):
            self.report(where, path, "has a credential-bearing key name", value)

    def walk(self, where: str, node: object, path: list[str], key: str, depth: int) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                self.walk(where, v, path + [str(k)], str(k), depth)
        elif isinstance(node, list):
            for v in node:
                self.walk(where, v, path + ["[]"], key, depth)
        else:
            self.check_leaf(where, path, key, node)
            if isinstance(node, str) and depth < NESTED_YAML_DEPTH and ("\n" in node or node.lstrip()[:1] in "{["):
                self.check_document(f"{where} {_path_text(path)} (nested)", node, depth + 1)

    def check_document(self, where: str, text: str, depth: int = 0) -> None:
        import yaml

        self.scan_text(where, text)
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError:
            return  # not YAML: the text rules above still applied
        for doc in docs:
            if isinstance(doc, (dict, list)):
                self.walk(where, doc, [], "", depth)

    def check_configmap(self, obj: dict) -> None:
        meta = obj.get("metadata") or {}
        ns = meta.get("namespace")
        name = f"ConfigMap {ns + '/' if ns else ''}{meta.get('name', '<unnamed>')}"
        data = obj.get("data") or {}
        binary = obj.get("binaryData") or {}
        if not isinstance(data, dict) or not isinstance(binary, dict):
            raise Incomplete(f"{name}: data or binaryData is not a mapping")
        for key, value in data.items():
            where = f"{name} data[{key}]"
            self.check_leaf(where, [], str(key), value)
            if isinstance(value, str):
                self.check_document(where, value)
        for key, value in binary.items():
            where = f"{name} binaryData[{key}]"
            try:
                raw = base64.b64decode(str(value), validate=True)
            except (binascii.Error, ValueError) as exc:
                raise Incomplete(f"{where}: not valid base64") from exc
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                self.scan_text(where, raw.decode("latin-1"))
                continue
            self.check_leaf(where, [], str(key), text)
            self.check_document(where, text)


def configmaps(node: object) -> list[dict]:
    if not isinstance(node, dict):
        return []
    if node.get("kind") == "ConfigMap":
        return [node]
    if node.get("kind") == "List" or str(node.get("kind", "")).endswith("List"):
        out: list[dict] = []
        for item in node.get("items") or []:
            out.extend(configmaps(item))
        return out
    return []


def check_manifest(derived: Derived, text: str) -> list[str]:
    import yaml

    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise Incomplete(f"manifest is not valid YAML: {exc.__class__.__name__}") from exc
    found = [cm for doc in docs for cm in configmaps(doc)]
    if not found:
        raise Incomplete("manifest holds no ConfigMap; the render is incomplete")
    checker = Checker(derived)
    for cm in found:
        checker.check_configmap(cm)
    return checker.findings


# ---------------------------------------------------------------- values.yaml


def check_values(text: str) -> list[str]:
    import yaml

    try:
        values = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise Incomplete(f"values file is not valid YAML: {exc.__class__.__name__}") from exc
    if not isinstance(values, dict):
        raise Incomplete("values file is not a mapping")
    findings: list[str] = []
    seen: set[str] = set()

    def leaf(path: str, key: str, value: object) -> None:
        if path in VALUES_ALLOWLIST:
            seen.add(path)
            kind = VALUES_ALLOWLIST[path]
            text_value = "" if value is None else str(value)
            if kind == "reference" and text_value and not K8S_NAME.match(text_value):
                findings.append(f"{path}: a reference must be a Kubernetes object name (value withheld)")
            elif kind == "secret-key-name" and not SECRET_KEY_NAME.match(text_value):
                findings.append(f"{path}: a Secret key name must match {SECRET_KEY_NAME.pattern} (value withheld)")
            elif kind == "removed-must-be-empty" and text_value:
                findings.append(f"{path}: removed credential input must stay empty (value withheld)")
            return
        if CREDENTIAL_NAME.search(normalise_name(key)) or normalise_name(key) in REFERENCE_KEYS:
            findings.append(
                f"{path}: credential-named chart input is not in the explicit allowlist; supply credentials "
                "through an existingSecret reference and list the reference in VALUES_ALLOWLIST"
            )

    def walk(node: object, path: str, key: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else str(k), str(k))
        elif isinstance(node, list):
            for v in node:
                walk(v, f"{path}[]", key)
        else:
            leaf(path, key, node)

    walk(values, "", "")
    for path in sorted(set(VALUES_ALLOWLIST) - seen):
        findings.append(f"{path}: listed in VALUES_ALLOWLIST but absent from the values file")
    return findings


# ---------------------------------------------------------------- CLI


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_derive = sub.add_parser("derive")
    p_derive.add_argument("--config-dir", required=True, type=pathlib.Path)
    p_check = sub.add_parser("check")
    p_check.add_argument("--config-dir", required=True, type=pathlib.Path)
    p_check.add_argument("manifest", type=pathlib.Path)
    p_values = sub.add_parser("values")
    p_values.add_argument("values_file", type=pathlib.Path)
    args = parser.parse_args(argv)

    try:
        try:
            import yaml  # noqa: F401
        except ImportError as exc:
            raise Incomplete("PyYAML is not importable by this interpreter") from exc
        if args.cmd == "derive":
            d = derive(args.config_dir)
            print(
                f"derived {len(d.keys)} credential keys, {len(d.envs)} credential env names, "
                f"{len(d.path_keys)} credential file keys "
                f"(envBindings secret entries {d.secret_bindings}, newSecretFile calls {d.secret_files}, "
                f"directCredentialEnv {d.direct_envs})"
            )
            for k in sorted(d.keys):
                print(f"  key  {k}")
            for e in sorted(d.envs):
                print(f"  env  {e}")
            for k in sorted(d.path_keys):
                print(f"  file {k}")
            return 0
        if args.cmd == "check":
            d = derive(args.config_dir)
            findings = check_manifest(d, args.manifest.read_text(encoding="utf-8"))
        else:
            findings = check_values(args.values_file.read_text(encoding="utf-8"))
    except Incomplete as exc:
        print(f"INCOMPLETE: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"INCOMPLETE: {exc.__class__.__name__}: {exc.filename}", file=sys.stderr)
        return 2
    if findings:
        for f in findings:
            print(f"CREDENTIAL: {f}", file=sys.stderr)
        print(f"{len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
