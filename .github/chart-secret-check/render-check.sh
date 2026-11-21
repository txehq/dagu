#!/usr/bin/env bash
# Render the Dagu chart across its value combinations and fail when a
# credential reaches any ConfigMap (TXE-8035). CI runs it in HelmChartCI.
#
# Usage: render-check.sh WORKDIR
#   WORKDIR  an existing, empty directory the caller owns (mktemp -d). Every
#            render and log goes there; nothing is deleted.
# Environment: HELM (default helm), PYTHON (default python3).
# Run from the repository root. Offline: helm template only, no --validate,
# no cluster, no network.
set -euo pipefail

work="${1:?usage: render-check.sh WORKDIR}"
if [[ ! -d "${work}" ]] || [[ -n "$(ls -A "${work}")" ]]; then
  echo "::error::WORKDIR must be an existing empty directory: ${work}"
  exit 2
fi

helm_bin="${HELM:-helm}"
python_bin="${PYTHON:-python3}"
here=".github/chart-secret-check"
chart="charts/dagu"
config_dir="internal/cmn/config"
checker=("${python_bin}" -I "${here}/check_configmap_secrets.py")

render() {
  # render OUTPUT CHART [helm args...]
  local out="$1" src="$2"
  shift 2
  "${helm_bin}" template dagu "${src}" --namespace dagu --kube-version 1.35.0 "$@" >"${out}"
}

# A finding's text must never echo the value it found.
assert_no_value() {
  local log="$1" value="$2"
  if grep -Fq -- "${value}" "${log}"; then
    echo "::error::${log} repeats a planted value; findings must withhold values"
    exit 1
  fi
}

echo "== checker unit tests"
"${python_bin}" -I "${here}/test_check_configmap_secrets.py" >"${work}/unit-tests.log" 2>&1 || {
  cat "${work}/unit-tests.log"
  exit 1
}
tail -n 3 "${work}/unit-tests.log"

echo "== derive credential keys from ${config_dir}"
"${checker[@]}" derive --config-dir "${config_dir}" >"${work}/derive.txt"
head -n 1 "${work}/derive.txt"

echo "== values.yaml inputs"
"${checker[@]}" values "${chart}/values.yaml"

echo "== value matrix"
count=0
for values in "${here}"/values/*.yaml; do
  name="$(basename "${values}" .yaml)"
  render "${work}/${name}.yaml" "${chart}" -f "${values}"
  echo "-- ${name}"
  "${checker[@]}" check --config-dir "${config_dir}" "${work}/${name}.yaml"
  count=$((count + 1))
done
if [[ "${count}" -lt 8 ]]; then
  echo "::error::expected at least 8 value fixtures, rendered ${count}"
  exit 1
fi

# The references render where they belong: the token key reaches the server
# container from its Secret, and the extraEnv literal stays in the Deployment.
every="${work}/08-every-reference-distributed.yaml"
test "$(grep -Fc 'name: DAGU_AUTH_TOKEN_SECRET' "${every}")" -eq 1
grep -Fq 'name: "fake-ref-token"' "${every}"
grep -Fq 'key: "fake-ref-token-key"' "${every}"
grep -Fq 'value: FAKE-SECRET-VALUE-extra-env' "${every}"
if grep -Fq 'secret:' "${work}/01-standalone-default.yaml"; then
  echo "::error::the default render still has a secret: key"
  exit 1
fi
if grep -Fq 'DAGU_AUTH_TOKEN_SECRET' "${work}/01-standalone-default.yaml"; then
  echo "::error::the default render references a token Secret it was not given"
  exit 1
fi

echo "== template-time refusals"
expect_refusal() {
  # expect_refusal NAME EXPECTED_TEXT [helm args...]
  local name="$1" expected="$2"
  shift 2
  local log="${work}/refusal-${name}.log"
  if render "${work}/refusal-${name}.yaml" "${chart}" "$@" 2>"${log}"; then
    echo "::error::rendering was expected to fail: ${name}"
    exit 1
  fi
  if ! grep -Fq -- "${expected}" "${log}"; then
    echo "::error::rendering failed for an unexpected reason: ${name}"
    cat "${log}"
    exit 1
  fi
  echo "-- ${name}: refused"
}
expect_refusal removed-token-secret \
  "auth.builtin.token.secret is no longer supported" \
  --set-string auth.builtin.token.secret=FAKE-SECRET-VALUE-legacy-token
assert_no_value "${work}/refusal-removed-token-secret.log" FAKE-SECRET-VALUE-legacy-token
expect_refusal token-secret-key-empty \
  "auth.builtin.token.secretKey is required" \
  --set-string auth.builtin.token.existingSecret=fake-ref-token \
  --set-string auth.builtin.token.secretKey=
expect_refusal token-extra-env-conflict \
  "conflicts with auth.builtin.token.existingSecret" \
  --set-string auth.builtin.token.existingSecret=fake-ref-token \
  --set-string 'extraEnv[0].name=DAGU_AUTH_TOKEN_SECRET' \
  --set-string 'extraEnv[0].value=FAKE-SECRET-VALUE-extra'
expect_refusal token-file-extra-env-conflict \
  "conflicts with auth.builtin.token.existingSecret" \
  --set-string auth.builtin.token.existingSecret=fake-ref-token \
  --set-string 'extraEnv[0].name=DAGU_AUTH_TOKEN_SECRET_FILE' \
  --set-string 'extraEnv[0].value=/etc/dagu-token/token'

echo "== planted leaks through the chart must fail the check"
planted=0
for plant in "${here}"/planted/*.yaml; do
  name="$(basename "${plant}" .yaml)"
  copy="${work}/chart-${name}"
  mkdir "${copy}"
  cp -R "${chart}/." "${copy}/"
  cp "${plant}" "${copy}/templates/zz-planted.yaml"
  render "${work}/planted-${name}.yaml" "${copy}"
  set +e
  "${checker[@]}" check --config-dir "${config_dir}" "${work}/planted-${name}.yaml" \
    >"${work}/planted-${name}.log" 2>&1
  rc=$?
  set -e
  if [[ "${rc}" -ne 1 ]]; then
    echo "::error::planted leak ${name}: checker exited ${rc}, expected 1 (a finding)"
    cat "${work}/planted-${name}.log"
    exit 1
  fi
  assert_no_value "${work}/planted-${name}.log" fake-planted-value
  echo "-- ${name}: caught"
  planted=$((planted + 1))
done
if [[ "${planted}" -lt 4 ]]; then
  echo "::error::expected at least 4 planted leaks, ran ${planted}"
  exit 1
fi

echo "render check passed: ${count} value fixtures clean, 4 refusals, ${planted} planted leaks caught"
