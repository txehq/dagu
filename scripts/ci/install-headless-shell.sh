#!/usr/bin/env bash
# Install Chrome's headless shell for a Go test shard whose plan runs the
# DevTools gate's tests, and export CHROME_HEADLESS_SHELL_PATH for them
# (TXE-7856: TestRealHeadlessShellIsRefused, required under CI).
#
# The version is Playwright's, as ui/pnpm-lock.yaml pins it: one pin for
# every Playwright browser CI installs. A shard whose plan does not run the
# gate's package installs nothing.
#
# usage: install-headless-shell.sh PLAN_FILE
set -euo pipefail

[[ $# -eq 1 ]] || {
  echo "usage: $0 PLAN_FILE" >&2
  exit 2
}
plan=$1
if ! grep -q 'internal/browserhost/devtoolsgate' "${plan}"; then
  echo "this shard does not run the DevTools gate's tests; no headless shell"
  exit 0
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
versions="$(sed -n 's/^  playwright@\([0-9][0-9.]*\):$/\1/p' "${root}/ui/pnpm-lock.yaml" | sort -u)"
if [[ -z "${versions}" || "$(wc -l <<<"${versions}")" -ne 1 ]]; then
  echo "ui/pnpm-lock.yaml pins no single Playwright version: '${versions}'" >&2
  exit 1
fi

: "${RUNNER_TEMP:?}" "${GITHUB_ENV:?}"
export PLAYWRIGHT_BROWSERS_PATH="${RUNNER_TEMP}/ms-playwright"
if [[ -r /etc/os-release ]] && grep -q '^ID=ubuntu' /etc/os-release; then
  release="$(sed -n 's/^VERSION_ID="\{0,1\}\([0-9.]*\)"\{0,1\}$/\1/p' /etc/os-release)"
  if [[ "${release}" != "22.04" && "${release}" != "24.04" ]]; then
    # Playwright downloads its builds by the host's Ubuntu release, and the
    # pinned release knows none newer than 24.04 (the E2E job pins its
    # runner for the same reason); the 24.04 build is the one to take.
    export PLAYWRIGHT_HOST_PLATFORM_OVERRIDE="ubuntu24.04-x64"
  fi
fi

started=$SECONDS
npx --yes "playwright@${versions}" install chromium-headless-shell
shell="$(find "${PLAYWRIGHT_BROWSERS_PATH}" -type f \( -name chrome-headless-shell -o -name chrome-headless-shell.exe \) | head -n 1)"
if [[ -z "${shell}" ]]; then
  echo "Playwright ${versions} installed no chrome-headless-shell under ${PLAYWRIGHT_BROWSERS_PATH}" >&2
  exit 1
fi
echo "CHROME_HEADLESS_SHELL_PATH=${shell}" >>"${GITHUB_ENV}"
echo "headless shell from Playwright ${versions}: ${shell}"
"${shell}" --version || true
echo "installed in $((SECONDS - started)) s"
