// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The commands the developer setup guide shows (TXE-4938). They follow the
// shipped installer and CLI: txe/developer/install.sh, its README and the
// txe-dagu-jobs skill. Nothing here runs anything; the page only prints text
// for a person to copy.

// The fork that carries the TXE CLI. It publishes no release downloads, so
// the guide builds the CLI from a tag of it, as install.sh --tag does.
export const DAGU_REPO = 'https://github.com/txehq/dagu.git';

// The earliest tag with every command the guide uses (machine create).
export const MIN_TAG = 'txe-v2.18.2-14';

// The tags install.sh accepts.
const TAG_PATTERN = /^txe-v(\d+)\.(\d+)\.(\d+)-(\d+)$/;

export function isTag(tag: string): boolean {
  return TAG_PATTERN.test(tag);
}

// tagVersion is what `dagu version` reports for a tag's build, the way
// install.sh derives it: txe-v2.18.2-14 is 2.18.2-txe.14.
export function tagVersion(tag: string): string | undefined {
  const m = TAG_PATTERN.exec(tag);
  return m ? `${m[1]}.${m[2]}.${m[3]}-txe.${m[4]}` : undefined;
}

// isBeforeMinTag reports a well-formed tag older than MIN_TAG.
export function isBeforeMinTag(tag: string): boolean {
  const a = TAG_PATTERN.exec(tag);
  const b = TAG_PATTERN.exec(MIN_TAG);
  if (!a || !b) return false;
  for (let i = 1; i <= 4; i++) {
    const d = Number(a[i]) - Number(b[i]);
    if (d !== 0) return d < 0;
  }
  return false;
}

// shellQuote makes one POSIX shell word of a value.
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

// The API path the CLI appends to a hub address that names no path.
const DEFAULT_API_PATH = '/api/v1';

// hubAddress is the address `dagu txe login --hub` takes for the hub serving
// this page. The CLI adds /api/v1 to an address with no path and keeps a
// path it is given as the API root, so behind a base path or another API
// path the API root itself is given. apiURL is the page's configured API
// URL: a path on this origin, or an absolute URL.
export function hubAddress(origin: string, apiURL: string): string {
  let url: URL;
  try {
    url = new URL(apiURL, origin);
  } catch {
    return origin;
  }
  const path = url.pathname.replace(/\/+$/, '');
  url.search = '';
  url.hash = '';
  if (path === DEFAULT_API_PATH || path === '') {
    return url.origin;
  }
  return `${url.origin}${path}`;
}

// hubAddressRefused reports an address the CLI refuses: it signs in only over
// https, except to this machine itself.
export function hubAddressRefused(address: string): boolean {
  let url: URL;
  try {
    url = new URL(address);
  } catch {
    return true;
  }
  if (url.protocol === 'https:') return false;
  if (url.protocol !== 'http:') return true;
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return !(
    host === 'localhost' ||
    host === '::1' ||
    /^127(\.\d{1,3}){3}$/.test(host)
  );
}

// The commands for a tag, or for a placeholder when the tag is not one
// install.sh accepts.
export function setupCommands(tag: string, hub: string) {
  const t = isTag(tag) ? tag : '<accepted tag>';
  const dir = isTag(tag) ? `txe-dagu-${tag}` : 'txe-dagu';
  return {
    prerequisites: [
      'command -v git go python3 bash',
      `export PATH="$HOME/.local/bin:$PATH"   # add this line to ~/.zshrc or ~/.bashrc`,
    ].join('\n'),
    install: [
      `git clone --depth 1 --branch ${t} ${DAGU_REPO} ${dir}`,
      `cd ${dir}`,
      `txe/developer/install.sh --tag ${t}`,
    ].join('\n'),
    check: ['txe/developer/install.sh --check', 'dagu version'].join('\n'),
    login: `dagu txe login --hub ${shellQuote(hub)}`,
    // The sign-in returns to a one-shot listener on 127.0.0.1 at the port in
    // the printed address, so a browser elsewhere reaches it only through a
    // forward of that same port.
    sshForward: 'ssh -L <port>:127.0.0.1:<port> <you>@<that machine>',
    loginNoBrowser: `dagu txe login --hub ${shellQuote(hub)} --no-browser`,
    whoami: 'dagu txe whoami',
    machineCreate: 'dagu txe machine create',
    doctor: 'dagu txe doctor',
    enrol:
      'dagu txe enrol --client-id <this machine’s worker client> --wait 15m',
  };
}

// The smoke test job (txe/developer/smoke). {{STAMP}} and {{EXPIRES_AT}} are
// filled in by the shell when the person runs the command, so the lifetime
// is fifteen minutes from then, never a date fixed when the page was loaded.
// The template must stay free of $, ` and \, which an unquoted here-document
// would expand.
export const SMOKE_JOB_TEMPLATE = `schema: 1
job_key: dev-setup-smoke-{{STAMP}}
title: Developer setup smoke test
purpose: >-
  Shows that this machine's worker runs a job the hub schedules and that the
  result reaches the hub. It calls no external service: each run prints one
  line and writes only its result.json, which is published to the hub. The
  job retires itself when its lifetime ends.
project:
  key: txe.local/dev-setup-smoke
  name: developer setup smoke test
targets:
  - kind: example.smoke
    environment: local
    stable_id:
      id: dev-setup-smoke-{{STAMP}}
    display_name: developer setup smoke test
    existence_check: event_only
schedule:
  cron: "* * * * *"
  timezone: UTC
  timeout_sec: 60
package:
  include: [run.sh]
  entrypoint: [./run.sh]
expected_outcome:
  success_criteria:
    - Each run exits 0, prints one line with ok true, and publishes result.json.
  deliverables:
    - name: result
      path: result.json
      delivery: hub
      required: true
lifetime:
  expires_at: "{{EXPIRES_AT}}"
review_policy:
  cadence: "0 9 * * *"
  brief: >-
    A smoke test of one developer's setup. A failed run means this machine's
    worker or its enrolment needs its owner; take no other action.
`;

export const SMOKE_SCRIPT = `#!/bin/sh
# One harmless run: print a result line and publish it as result.json.
set -eu
line="$(printf '{"ok":true,"observed_at":"%s"}' "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
printf '%s\\n' "$line" > "$TXE_RUN_OUTPUT_DIR/result.json"
printf '%s\\n' "$line"
`;

// The session the smoke test's registration records as its author.
export const SMOKE_SESSION = 'dev-setup-smoke';

// smokeCommands writes the smoke test into a new directory and prints the
// steps that use it. Files are written by absolute path and the shell enters
// the directory last, so a failure leaves nothing in the current directory
// and never exits the person's shell. The stamp and the lifetime come from the shell's clock
// (BSD date on macOS, GNU date on Linux).
export function smokeCommands() {
  const job = SMOKE_JOB_TEMPLATE.split('{{STAMP}}')
    .join('${stamp}')
    .split('{{EXPIRES_AT}}')
    .join('${expires}');
  const create = [
    // Seconds and random hex: two people of one owner in the same minute
    // get different job keys.
    'stamp="$(date -u +%Y%m%d%H%M%S)-$(od -An -N3 -tx1 /dev/urandom | tr -d \' \\n\')"',
    'expires="$(date -u -v+15M +%Y-%m-%dT%H:%M:00Z 2>/dev/null || date -u -d \'+15 minutes\' +%Y-%m-%dT%H:%M:00Z)"',
    'smoke_dir="$HOME/txe-dev-setup-smoke/$stamp"',
    'mkdir -p "$smoke_dir"',
    'cat > "$smoke_dir/run.sh" <<\'EOF\'',
    SMOKE_SCRIPT.trimEnd(),
    'EOF',
    'chmod 0755 "$smoke_dir/run.sh"',
    'cat > "$smoke_dir/job.yaml" <<EOF',
    job.trimEnd(),
    'EOF',
    // The line that says it worked is printed only once in the directory.
    'cd "$smoke_dir" && echo "job key dev-setup-smoke-$stamp, expires $expires"',
  ].join('\n');
  return {
    create,
    dryRun: `dagu txe register -f job.yaml --session ${SMOKE_SESSION} --dry-run`,
    register: `dagu txe register -f job.yaml --session ${SMOKE_SESSION}`,
    inspect: 'dagu txe inspect <job id>',
    verify: 'dagu txe package verify <job id>',
  };
}
