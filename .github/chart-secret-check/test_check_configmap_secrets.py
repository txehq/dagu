#!/usr/bin/env python3
"""Tests for check_configmap_secrets.py (TXE-8035).

Run: python3 -I .github/chart-secret-check/test_check_configmap_secrets.py
Every credential here is an obvious fake. Token-shaped values are assembled at
run time so no scanner mistakes this file for a leak.
"""
from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import pathlib
import re
import sys
import tempfile
import textwrap
import unittest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
_spec = importlib.util.spec_from_file_location("check_configmap_secrets", HERE / "check_configmap_secrets.py")
assert _spec is not None and _spec.loader is not None
c = importlib.util.module_from_spec(_spec)
sys.modules["check_configmap_secrets"] = c
_spec.loader.exec_module(c)

FAKE = "fake-test-value-do-not-use"

LOADER = textwrap.dedent(
    """\
    package config

    import "fmt"

    var envBindings = []envBinding{
    \t// A comment with a { brace and secret: true must not count.
    \t{key: "log_format", env: "LOG_FORMAT"},
    \t{key: "auth.basic.password", env: "AUTH_BASIC_PASSWORD", secret: true},
    \t{key: "auth.basic.password_file", env: "AUTH_BASIC_PASSWORD_FILE", isPath: true, secret: true},
    \t{key: hubKeyFileKey, env: hubKeyFileEnv, secret: true},
    \t{key: "license.key", env: "LICENSE_KEY", secret: true},
    \t{key: "auth.proxy.enabled", env: "AUTH_PROXY_ENABLED", requires: SectionServer},
    \t{key: forkFeaturesKey, env: forkFeaturesEnv},
    %EXTRA%
    }

    func (l *ConfigLoader) loadSecretFiles(def *Definition) error {
    \tvar secrets []secretFile
    \tif def.Auth != nil {
    \t\tsecrets = append(secrets, newSecretFile("auth.oidc.client_secret", def.Auth.F, &def.Auth.S))
    \t}
    \tfor i := range def.RemoteNodes {
    \t\tnode := &def.RemoteNodes[i]
    \t\tsecrets = append(secrets,
    \t\t\tnewSecretFile(fmt.Sprintf("remote_nodes[%d].auth_token", i), node.F, &node.T),
    \t\t)
    \t}
    %SECRETFILES%
    \treturn nil
    }
    """
)
CONSTS = textwrap.dedent(
    """\
    package config

    const (
    \thubKeyFileKey = "coordinator.auth.hub_key_file"
    \thubKeyFileEnv = "COORDINATOR_AUTH_HUB_KEY_FILE"

    \tforkKey         = "license.fork_policy"
    \tforkFeaturesKey = forkKey + ".features"
    \tforkFeaturesEnv = "LICENSE_FORK_FEATURES"
    )
    """
)
CRED_ENV = textwrap.dedent(
    """\
    package config

    var directCredentialEnv = []string{
    \t"ENCRYPTION_KEY", // the secret store's key
    %DIRECT%
    }
    """
)


class FakePackage:
    def __init__(self, extra="", secret_files="", direct="", loader=None, cred_env=None, files=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        texts = {
            "loader.go": loader if loader is not None else LOADER.replace("%EXTRA%", extra).replace("%SECRETFILES%", secret_files),
            "transport_auth.go": CONSTS,
            "credential_env.go": cred_env if cred_env is not None else CRED_ENV.replace("%DIRECT%", direct),
            "loader_test.go": 'package config\nvar envBindings = []envBinding{{key: "x", env: "X"}}\n',
        }
        texts.update(files or {})
        for name, text in texts.items():
            if text is not None:
                (self.dir / name).write_text(text, encoding="utf-8")

    def __enter__(self):
        return self.dir

    def __exit__(self, *exc):
        self.tmp.cleanup()


def derive_fake(**kw):
    with FakePackage(**kw) as d:
        return c.derive(d)


class DeriveRealTree(unittest.TestCase):
    def test_real_config_package(self):
        d = c.derive(REPO / "internal" / "cmn" / "config")
        for key in (
            "auth.builtin.token.secret",
            "auth.basic.password",
            "auth.oidc.client_secret",
            "auth.builtin.initial_admin.password",
            "license.key",
            "secrets.vault.token",
            "remote_nodes[].auth_token",
            "remote_nodes[].basic_auth_password",
        ):
            self.assertIn(key, d.keys)
        for env in ("DAGU_AUTH_TOKEN_SECRET", "DAGU_AUTH_OIDC_CLIENT_SECRET", "DAGU_ENCRYPTION_KEY", "DAGU_LICENSE"):
            self.assertIn(env, d.envs)
        # Keys bound through Go constants (transport_auth.go) are resolved, not skipped.
        self.assertIn("coordinator.auth.hub_key_file", d.path_keys)
        self.assertIn("worker.auth.credential_file", d.path_keys)
        self.assertIn("auth.builtin.token.secret_file", d.path_keys)
        self.assertNotIn("auth.builtin.token.secret_file", d.keys)


class DeriveFake(unittest.TestCase):
    def test_valid_package(self):
        d = derive_fake()
        self.assertEqual(
            d.keys,
            {"auth.basic.password", "license.key", "auth.oidc.client_secret", "remote_nodes[].auth_token"},
        )
        self.assertEqual(d.envs, {"DAGU_AUTH_BASIC_PASSWORD", "DAGU_LICENSE_KEY", "DAGU_ENCRYPTION_KEY"})
        self.assertEqual(d.path_keys, {"auth.basic.password_file", "coordinator.auth.hub_key_file"})
        self.assertEqual((d.secret_bindings, d.secret_files, d.direct_envs), (4, 2, 1))

    def test_new_secret_binding_is_picked_up(self):
        d = derive_fake(extra='\t{key: "new.thing.api_token", env: "NEW_THING_API_TOKEN", secret: true},')
        self.assertIn("new.thing.api_token", d.keys)
        self.assertIn("DAGU_NEW_THING_API_TOKEN", d.envs)

    def test_concatenated_constant_resolves(self):
        # loader.go binds license.fork_policy keys as forkPolicyKey + ".features".
        d = derive_fake(
            extra='\t{key: secretForkKey, env: "FORK_TOKEN", secret: true},',
            files={"more.go": 'package config\nconst secretForkKey = forkKey + ".token"\n'},
        )
        self.assertIn("license.fork_policy.token", d.keys)

    def test_concatenation_with_unknown_part(self):
        self.assertIncomplete(
            extra="\t{key: badKey, env: \"BAD\", secret: true},",
            files={"more.go": "package config\nconst badKey = undeclaredPrefix + \".x\"\n"},
        )

    def test_concatenation_with_non_string_part(self):
        self.assertIncomplete(
            extra="\t{key: badKey, env: \"BAD\", secret: true},",
            files={"more.go": "package config\nconst badKey = forkKey + fmt.Sprint(1)\n"},
        )

    def test_constant_declared_twice_differently(self):
        self.assertIncomplete(files={"more.go": 'package config\nfunc f() {\n\tconst hubKeyFileKey = "elsewhere"\n}\n'})

    def test_new_secret_file_is_picked_up(self):
        d = derive_fake(secret_files='\tsecrets = append(secrets, newSecretFile("git_sync.auth.token", a, &b))')
        self.assertIn("git_sync.auth.token", d.keys)

    def assertIncomplete(self, **kw):
        with self.assertRaises(c.Incomplete):
            derive_fake(**kw)

    def test_missing_envbindings(self):
        self.assertIncomplete(loader=LOADER.replace("var envBindings", "var otherBindings").replace("%EXTRA%", "").replace("%SECRETFILES%", ""))

    def test_empty_envbindings(self):
        loader = 'package config\nvar envBindings = []envBinding{\n}\nfunc (l *ConfigLoader) loadSecretFiles(def *Definition) error {\nnewSecretFile("a.b", x, &y)\nreturn nil\n}\n'
        self.assertIncomplete(loader=loader)

    def test_zero_secret_bindings(self):
        loader = LOADER.replace(", secret: true", "").replace("%EXTRA%", "").replace("%SECRETFILES%", "")
        self.assertIncomplete(loader=loader)

    def test_new_syntax_beside_recognised_entries(self):
        # One recognised entry must not hide a skipped new form.
        self.assertIncomplete(extra='\tsecretBinding("new.key", "NEW_KEY"),')

    def test_positional_entry(self):
        self.assertIncomplete(extra='\t{"new.key", "NEW_KEY", false, SectionNone, true},')

    def test_unknown_field(self):
        self.assertIncomplete(extra='\t{key: "a.b", env: "A_B", secret: true, scope: Global},')

    def test_unresolved_identifier(self):
        self.assertIncomplete(extra='\t{key: someUndeclaredKey, env: "A_B", secret: true},')

    def test_secret_not_literal(self):
        self.assertIncomplete(extra='\t{key: "a.b", env: "A_B", secret: isSecret},')

    def test_append_outside_declaration(self):
        files = {"extra.go": 'package config\nfunc init() {\n\tenvBindings = append(envBindings, envBinding{key: "a.b", env: "A_B", secret: true})\n}\n'}
        self.assertIncomplete(files=files)

    def test_secret_file_key_not_literal(self):
        self.assertIncomplete(secret_files="\tsecrets = append(secrets, newSecretFile(keyVar, a, &b))")

    def test_secret_file_unsupported_format(self):
        self.assertIncomplete(secret_files='\tsecrets = append(secrets, newSecretFile(fmt.Sprintf("x.%s.token", n), a, &b))')

    def test_no_secret_file_calls(self):
        loader = LOADER.replace("newSecretFile", "otherHelper").replace("%EXTRA%", "").replace("%SECRETFILES%", "")
        self.assertIncomplete(loader=loader)

    def test_missing_direct_credential_env(self):
        self.assertIncomplete(cred_env="package config\n")

    def test_empty_direct_credential_env(self):
        self.assertIncomplete(cred_env="package config\nvar directCredentialEnv = []string{\n}\n")

    def test_direct_credential_env_not_literal(self):
        self.assertIncomplete(direct="\tlicenseEnvName,")

    def test_missing_credential_env_file(self):
        self.assertIncomplete(cred_env=None, files={"credential_env.go": None})

    def test_unparseable_source(self):
        self.assertIncomplete(extra='\t{key: "unterminated, env: "X"},')

    def test_cli_exit_2_on_incomplete(self):
        with FakePackage(loader="package config\n") as d, contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(c.main(["derive", "--config-dir", str(d)]), 2)
        self.assertIn("INCOMPLETE", err.getvalue())


def cm(data=None, binary=None, name="cfg"):
    doc = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": "dagu"}}
    if data is not None:
        doc["data"] = data
    if binary is not None:
        doc["binaryData"] = binary
    return doc


def manifest(*docs):
    import yaml

    return yaml.safe_dump_all(list(docs), sort_keys=False)


class CheckManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.derived = derive_fake()

    def findings(self, *docs):
        out = c.check_manifest(self.derived, manifest(*docs))
        for f in out:
            self.assertNotIn(FAKE, f, "a finding must withhold the value")
        return out

    def assertFinds(self, *docs):
        self.assertTrue(self.findings(*docs), "expected a finding")

    def assertClean(self, *docs):
        self.assertEqual(self.findings(*docs), [])

    def dagu_yaml(self, body):
        return cm({"dagu.yaml": textwrap.dedent(body)})

    def test_clean_chart_shape(self):
        self.assertClean(
            self.dagu_yaml(
                """\
                auth:
                  mode: "builtin"
                  builtin:
                    token:
                      ttl: "24h"
                  oidc:
                    client_id: "ci-client"
                    role_mapping:
                      groups_claim: "groups"
                paths:
                  api_keys_dir: /data/api-keys
                """
            )
        )

    def test_empty_secret_is_not_a_credential(self):
        self.assertClean(self.dagu_yaml('auth:\n  builtin:\n    token:\n      secret: ""\n'))

    def test_token_secret_in_dagu_yaml(self):
        self.assertFinds(self.dagu_yaml(f'auth:\n  builtin:\n    token:\n      secret: "{FAKE}"\n'))

    def test_derived_key_matches_case_insensitively(self):
        self.assertFinds(self.dagu_yaml(f"Auth:\n  Basic:\n    Password: {FAKE}\n"))

    def test_derived_list_key(self):
        self.assertFinds(self.dagu_yaml(f"remote_nodes:\n  - name: a\n    auth_token: {FAKE}\n"))

    def test_derived_key_with_neutral_name(self):
        # license.key: the leaf name alone says nothing; the derived path does.
        self.assertFinds(self.dagu_yaml(f"license:\n  key: {FAKE}\n"))

    def test_env_style_data_key(self):
        self.assertFinds(cm({"DAGU_AUTH_BASIC_PASSWORD": FAKE}))

    def test_direct_credential_env_key(self):
        self.assertFinds(cm({"DAGU_ENCRYPTION_KEY": FAKE}))

    def test_env_file_lines(self):
        self.assertFinds(cm({"dagu.env": f"DAGU_LICENSE_KEY={FAKE}\n"}))
        self.assertFinds(cm({"app.env": f"export DB_PASSWORD={FAKE}\n"}))
        self.assertClean(cm({"app.env": "LOG_LEVEL=debug\n"}))

    def test_binary_data_is_decoded(self):
        payload = base64.b64encode(f"auth:\n  oidc:\n    client_secret: {FAKE}\n".encode()).decode()
        self.assertFinds(cm(binary={"extra.yaml": payload}))
        clean = base64.b64encode(b"auth:\n  mode: builtin\n").decode()
        self.assertClean(cm(binary={"extra.yaml": clean}))

    def test_binary_data_not_base64(self):
        with self.assertRaises(c.Incomplete):
            self.findings(cm(binary={"x": "not base64 !!"}))

    def test_every_configmap_is_checked(self):
        self.assertFinds(self.dagu_yaml("auth:\n  mode: builtin\n"), cm({"settings.yaml": f"db:\n  password: {FAKE}\n"}, name="other"))

    def test_list_kind_is_checked(self):
        self.assertFinds({"apiVersion": "v1", "kind": "List", "items": [cm({"token": FAKE})]})

    def test_only_configmaps(self):
        secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "s"}, "stringData": {"password": FAKE}}
        self.assertClean(self.dagu_yaml("auth:\n  mode: builtin\n"), secret)

    def test_nested_yaml_string(self):
        inner = f"database:\n  password: {FAKE}\n"
        self.assertFinds(cm({"settings.yaml": manifest({"embedded": inner})}))

    def test_value_shapes(self):
        pem = "-----BEGIN " + "RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"
        gh = "gh" + "p_" + "A1b2C3d4" * 5
        aws = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
        for value in (pem, gh, aws):
            with self.subTest(value=value[:6]):
                self.assertFinds(cm({"notes.txt": f"see {value} here"}))

    def test_secret_value_canary(self):
        self.assertFinds(cm({"anything": "x " + c.SECRET_VALUE_CANARY + "planted"}))

    def test_reference_canary_is_allowed(self):
        self.assertClean(cm({"refs.yaml": "existingSecret: fake-ref-token\nsecretName: fake-ref-tls\n"}))

    def test_reference_key_must_hold_a_name(self):
        self.assertFinds(cm({"refs.yaml": f"existingSecret: 'Not A Name {FAKE}'\n"}))

    def test_secret_key_is_not_exempt(self):
        # In S3-style configs secret_key is the credential itself.
        self.assertFinds(cm({"s3.yaml": f"s3:\n  secret_key: {FAKE}\n"}))
        self.assertFinds(cm({"refs.yaml": "secretKey: token-secret\n"}))

    def test_token_ttl_metadata_is_clean_but_token_leaf_is_not(self):
        self.assertClean(cm({"a.yaml": "token:\n  ttl: 24h\n"}))
        self.assertFinds(cm({"a.yaml": f"token: {FAKE}\n"}))

    def test_credential_file_keys(self):
        self.assertClean(cm({"a.yaml": "auth:\n  basic:\n    password_file: /etc/dagu/password\n"}))
        self.assertFinds(cm({"a.yaml": f"other:\n  password_file: {FAKE}\n"}))

    def test_credential_names(self):
        for key in ("password", "client_secret", "apiKey", "privateKey", "auth_token", "credentials", "passphrase"):
            with self.subTest(key=key):
                self.assertFinds(cm({"a.yaml": f"x:\n  {key}: {FAKE}\n"}))

    def test_list_of_credentials(self):
        self.assertFinds(cm({"a.yaml": f"tokens:\n  - {FAKE}\n"}))

    def test_boolean_at_credential_key(self):
        # A YAML bool at a credential key is still a non-empty credential
        # value; unquoted yes/on resolve to bools too.
        for body in (
            "auth:\n  basic:\n    password: true\n",
            "auth:\n  basic:\n    password: false\n",
            "auth:\n  basic:\n    password: yes\n",
            "license:\n  key: on\n",
            "DAGU_AUTH_BASIC_PASSWORD: true\n",
            "db:\n  token: true\n",
        ):
            with self.subTest(body=body):
                self.assertFinds(self.dagu_yaml(body))

    def test_boolean_flags_stay_clean(self):
        self.assertClean(
            self.dagu_yaml(
                """\
                auth:
                  proxy:
                    enabled: true
                    auto_signup: on
                  builtin:
                    password_disabled: true
                  basic:
                    password_file: true
                refs:
                  existingSecret: false
                """
            )
        )

    def test_non_utf8_binary_credential(self):
        not_utf8 = base64.b64encode(b"\xff").decode()  # inert single byte 0xff
        for key in ("token", "DAGU_AUTH_BASIC_PASSWORD", "existingSecret", "password_file"):
            with self.subTest(key=key):
                found = self.findings(cm(binary={key: not_utf8}))
                self.assertEqual(len(found), 1, found)
                self.assertIn("1 bytes", found[0])
        self.assertClean(cm(binary={"logo.png": not_utf8}))
        self.assertClean(cm(binary={"token": ""}))

    def test_no_configmap_is_incomplete(self):
        with self.assertRaises(c.Incomplete):
            self.findings({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "s"}})

    def test_invalid_manifest_is_incomplete(self):
        with self.assertRaises(c.Incomplete):
            c.check_manifest(self.derived, "a: [unclosed\n")


class CheckValues(unittest.TestCase):
    def test_chart_values_are_clean(self):
        text = (REPO / "charts" / "dagu" / "values.yaml").read_text(encoding="utf-8")
        self.assertEqual(c.check_values(text), [])

    def base(self):
        import yaml

        return yaml.safe_load((REPO / "charts" / "dagu" / "values.yaml").read_text(encoding="utf-8"))

    def run_values(self, values):
        import yaml

        out = c.check_values(yaml.safe_dump(values))
        for f in out:
            self.assertNotIn(FAKE, f)
        return out

    def test_new_literal_credential_input(self):
        v = self.base()
        v["auth"]["builtin"]["apiToken"] = ""
        self.assertTrue(self.run_values(v))

    def test_removed_token_secret_must_be_empty(self):
        v = self.base()
        v["auth"]["builtin"]["token"]["secret"] = FAKE
        self.assertTrue(self.run_values(v))

    def test_reference_must_be_a_name(self):
        v = self.base()
        v["license"]["existingSecret"] = "Not A Name " + FAKE
        self.assertTrue(self.run_values(v))

    def test_stale_allowlist_entry(self):
        v = self.base()
        del v["ingress"]["tls"]["secretName"]
        self.assertTrue(self.run_values(v))

    def test_unlisted_reference_key(self):
        v = self.base()
        v["extraThing"] = {"existingSecret": "fake-ref-x"}
        self.assertTrue(self.run_values(v))


def deployment(*env):
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "ui"},
        "spec": {"template": {"spec": {"containers": [{"name": "ui", "env": list(env)}]}}},
    }


def secret_env(name):
    return {"name": name, "valueFrom": {"secretKeyRef": {"name": "fake-ref-x", "key": "k"}}}


class EnvAliases(unittest.TestCase):
    """Names an extraEnv entry could use to override a Secret-backed variable.
    render-check.sh renders the chart with each and expects a refusal."""

    @classmethod
    def setUpClass(cls):
        cls.real = c.derive(REPO / "internal" / "cmn" / "config")
        cls.fake = derive_fake()

    def test_real_token_secret(self):
        self.assertEqual(
            c.conflict_names(self.real, "DAGU_AUTH_TOKEN_SECRET"),
            [
                "DAGU_AUTH_TOKEN_SECRET",
                "DAGU_AUTH.BUILTIN.TOKEN.SECRET",
                "DAGU_AUTH_TOKEN_SECRET_FILE",
                "DAGU_AUTH.BUILTIN.TOKEN.SECRET_FILE",
            ],
        )

    def test_real_chart_references(self):
        expected = {
            "DAGU_AUTH_BASIC_USERNAME": 2,
            "DAGU_AUTH_BASIC_PASSWORD": 4,
            "DAGU_LICENSE_KEY": 2,
            "DAGU_AUTH_OIDC_CLIENT_SECRET": 4,
        }
        for env, count in expected.items():
            with self.subTest(env=env):
                names = c.conflict_names(self.real, env)
                self.assertEqual(len(names), count, names)
                self.assertEqual(names[0], env)
                self.assertIn(c.APP_ENV_PREFIX + self.real.bindings[env].upper(), names)

    def test_direct_credential_env_stands_alone(self):
        self.assertEqual(c.conflict_names(self.fake, "DAGU_ENCRYPTION_KEY"), ["DAGU_ENCRYPTION_KEY"])

    def test_unknown_name_is_incomplete(self):
        with self.assertRaises(c.Incomplete):
            c.conflict_names(self.fake, "DAGU_NOT_A_SETTING")

    def test_manifest_secret_backed_only(self):
        text = manifest(
            cm({"dagu.yaml": "auth:\n  mode: basic\n"}),
            deployment(
                {"name": "DAGU_HOME", "value": "/data"},
                secret_env("DAGU_AUTH_BASIC_PASSWORD"),
                secret_env("OTHER_SECRET"),
                {"name": "DAGU_LICENSE_KEY", "valueFrom": {"configMapKeyRef": {"name": "x", "key": "k"}}},
            ),
        )
        self.assertEqual(
            c.env_aliases(self.fake, text),
            [
                "DAGU_AUTH_BASIC_PASSWORD",
                "DAGU_AUTH.BASIC.PASSWORD",
                "DAGU_AUTH_BASIC_PASSWORD_FILE",
                "DAGU_AUTH.BASIC.PASSWORD_FILE",
            ],
        )

    def test_chart_guards_fold_aliases(self):
        # Every extraEnv guard in configmap.yaml compares dagu.envConfigName,
        # so a new guard written against the raw name fails here.
        text = (REPO / "charts" / "dagu" / "templates" / "configmap.yaml").read_text(encoding="utf-8")
        guards = [
            line
            for line in text.splitlines()
            if re.search(r"\{\{-?\s*if\b.*\b(has|hasPrefix|hasSuffix|eq|contains)\b.*\.name\b", line)
        ]
        self.assertTrue(guards, "no extraEnv guard found in configmap.yaml")
        for line in guards:
            with self.subTest(line=line.strip()):
                self.assertIn('(include "dagu.envConfigName" .name)', line)


class Cli(unittest.TestCase):
    def test_exit_codes(self):
        with FakePackage() as d, tempfile.TemporaryDirectory() as t:
            clean = pathlib.Path(t) / "clean.yaml"
            leak = pathlib.Path(t) / "leak.yaml"
            empty = pathlib.Path(t) / "empty.yaml"
            clean.write_text(manifest(cm({"dagu.yaml": "auth:\n  mode: builtin\n"})))
            leak.write_text(manifest(cm({"dagu.yaml": f"auth:\n  basic:\n    password: {FAKE}\n"})))
            empty.write_text("")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(c.main(["check", "--config-dir", str(d), str(clean)]), 0)
                self.assertEqual(c.main(["check", "--config-dir", str(d), str(leak)]), 1)
                self.assertEqual(c.main(["check", "--config-dir", str(d), str(empty)]), 2)
                self.assertEqual(c.main(["check", "--config-dir", str(d), str(pathlib.Path(t) / "missing.yaml")]), 2)
            self.assertNotIn(FAKE, err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
