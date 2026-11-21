# Chart ConfigMap credential check (TXE-8035)

A ConfigMap is not a Secret: anyone allowed to read ConfigMaps in the namespace
reads every value in it. Until chart 2.0.7, `auth.builtin.token.secret` was
rendered into the config ConfigMap. This check fails CI when any credential
reaches any ConfigMap the Dagu chart renders.

| file | role |
|---|---|
| `check_configmap_secrets.py` | the checker: `derive`, `check`, `values` subcommands; exit 0 clean, 1 finding, 2 incomplete |
| `test_check_configmap_secrets.py` | its tests, including every fail-closed derivation case |
| `render-check.sh WORKDIR` | renders the chart for each `values/*.yaml`, checks every render, asserts the template-time refusals, and plants each `planted/*.yaml` into a copy of the chart to prove a leak fails |
| `values/` | the value combinations, with REFERENCE canaries (`fake-ref-*`, Secret names, allowed) and SECRET-VALUE canaries (`FAKE-SECRET-VALUE-*`, never allowed in a ConfigMap) |
| `planted/` | inert fake leaks: the old token shape, base64 `binaryData`, an env-style key, a nested YAML document |

CI: HelmChartCI "Validate Helm chart" runs `render-check.sh` on every change to
the chart, this directory or `internal/cmn/config`; the CI workflow's Cleanup
lint job runs the tests. Both use the runner's `python3 -I` with the image's
PyYAML (`python3-yaml`), as `.github/main-red-alert` does; the checker exits 2
if PyYAML does not import.

## What is derived, and the parser's limits

The credential keys come from Dagu's own source, so a new credential setting
is covered with no edit here: `envBindings` entries marked `secret: true`
(their YAML key and `DAGU_` variable), the keys passed to `newSecretFile` in
`loadSecretFiles`, and `directCredentialEnv` (`credential_env.go`). File-path
keys (`isPath`, or a name ending in `_file`) are recorded and not denied.

The parser is a small Go tokenizer, not a Go parser. It accepts only the forms
listed in the checker's docstring and exits 2 on anything else: an entry in
another form, an unknown field, an identifier that no string `const` in the
package binds, an assignment or append to `envBindings` elsewhere, a
`newSecretFile` key that is neither a literal nor `fmt.Sprintf` with `[%d]`, or
zero results. When Dagu's config code changes shape, the check goes red and the
parser is extended; it never passes on a partial read. A credential Dagu reads
by some other route is not derived; the key-name and value-shape rules are the
second line for it.

## Allowlists

Explicit and small. In a ConfigMap only `existingSecret` and `secretName` are
reference keys, and their values must be Kubernetes object names; `secretKey`
is not exempt (in S3-style configs `secret_key` is the credential). A
`<credential>_file` key must hold an absolute path. In `values.yaml`, every
credential-named input must appear in `VALUES_ALLOWLIST` with its kind, and an
entry missing from `values.yaml` is itself a finding.

Findings name the ConfigMap, the data key and the path, never the value.
