// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import {
  MIN_TAG,
  SMOKE_JOB_TEMPLATE,
  SMOKE_SCRIPT,
  hubAddress,
  hubAddressRefused,
  isBeforeMinTag,
  isTag,
  setupCommands,
  shellQuote,
  smokeCommands,
  tagVersion,
} from '../setupCommands';

const smokeDir = path.resolve(__dirname, '../../../../../txe/developer/smoke');

describe('hubAddress', () => {
  it.each([
    // The CLI adds /api/v1 to an address with no path.
    ['https://dag.example.com', '/api/v1', 'https://dag.example.com'],
    ['https://dag.example.com', '/api/v1/', 'https://dag.example.com'],
    // Behind a base path or another API path, the API root itself.
    ['https://example.com', '/dagu/api/v1', 'https://example.com/dagu/api/v1'],
    ['https://dag.example.com', '/rest', 'https://dag.example.com/rest'],
    // An absolute API URL names its own origin.
    [
      'https://ui.example.com',
      'https://api.example.com/api/v1',
      'https://api.example.com',
    ],
    ['http://127.0.0.1:18080', '/api/v1', 'http://127.0.0.1:18080'],
  ])('%s with %s is %s', (origin, apiURL, want) => {
    expect(hubAddress(origin, apiURL)).toBe(want);
  });
});

describe('hubAddressRefused', () => {
  it.each([
    ['https://dag.example.com', false],
    ['http://127.0.0.1:18080', false],
    ['http://localhost:8080', false],
    ['http://[::1]:8080', false],
    ['http://dag.example.com', true],
    ['ftp://dag.example.com', true],
    ['not a url', true],
  ])('%s refused: %s', (address, refused) => {
    expect(hubAddressRefused(address)).toBe(refused);
  });
});

describe('shellQuote', () => {
  it('makes one word the shell reads back unchanged', () => {
    for (const value of [
      'https://dag.example.com/a b',
      "https://x.example/it's",
      'https://x.example/$(touch nope)`id`',
    ]) {
      const out = spawnSync('sh', ['-c', `printf %s ${shellQuote(value)}`], {
        encoding: 'utf8',
      });
      expect(out.stdout).toBe(value);
    }
  });
});

describe('tags', () => {
  it('accepts what install.sh accepts', () => {
    expect(isTag('txe-v2.18.2-14')).toBe(true);
    expect(isTag('txe-v2.18.2-14 ')).toBe(false);
    expect(isTag('v2.18.2')).toBe(false);
    expect(isTag('txe-v2.18.2-14; rm -rf ~')).toBe(false);
  });

  it('derives the version dagu reports', () => {
    expect(tagVersion('txe-v2.18.2-14')).toBe('2.18.2-txe.14');
    expect(tagVersion('nope')).toBeUndefined();
  });

  it('orders tags numerically', () => {
    expect(isBeforeMinTag('txe-v2.18.2-13')).toBe(true);
    expect(isBeforeMinTag('txe-v2.18.2-9')).toBe(true);
    expect(isBeforeMinTag(MIN_TAG)).toBe(false);
    expect(isBeforeMinTag('txe-v2.18.2-100')).toBe(false);
    expect(isBeforeMinTag('txe-v2.19.0-1')).toBe(false);
  });

  it('shows a placeholder, never a malformed tag, in a command', () => {
    const cmd = setupCommands('txe-v2.18.2-14; id', 'https://dag.example.com');
    expect(cmd.install).not.toContain('; id');
    expect(cmd.install).toContain('--tag <accepted tag>');
  });

  it('builds the tag with the shipped installer', () => {
    const cmd = setupCommands(MIN_TAG, 'https://dag.example.com');
    expect(cmd.install).toBe(
      [
        `git clone --depth 1 --branch ${MIN_TAG} https://github.com/txehq/dagu.git txe-dagu-${MIN_TAG}`,
        `cd txe-dagu-${MIN_TAG}`,
        `txe/developer/install.sh --tag ${MIN_TAG}`,
      ].join('\n')
    );
    expect(cmd.login).toBe("dagu txe login --hub 'https://dag.example.com'");
  });
});

describe('the smoke test', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  // The page and txe/developer/smoke are one test: the Go test registers the
  // repository's files with the built CLI, and the page must print them.
  it('is the repository template', () => {
    expect(SMOKE_JOB_TEMPLATE).toBe(
      readFileSync(path.join(smokeDir, 'job.yaml'), 'utf8')
    );
    expect(SMOKE_SCRIPT).toBe(
      readFileSync(path.join(smokeDir, 'run.sh'), 'utf8')
    );
  });

  it('has nothing an unquoted here-document would expand', () => {
    expect(SMOKE_JOB_TEMPLATE).not.toMatch(/[$`\\]/);
  });

  // The command runs as a person pastes it: the files it writes are the
  // template with the shell's stamp and a lifetime three hours from now.
  it.each(['bash', 'zsh'])('writes the files when run in %s', (shell) => {
    const which = spawnSync('sh', ['-c', `command -v ${shell}`]);
    if (which.status !== 0) return;
    const home = mkdtempSync(path.join(tmpdir(), 'dev-setup-smoke-'));
    dirs.push(home);
    const before = Date.now();
    const cwd = mkdtempSync(path.join(tmpdir(), 'dev-setup-cwd-'));
    dirs.push(cwd);
    const out = spawnSync(shell, ['-c', smokeCommands().create + '\npwd'], {
      cwd,
      env: { HOME: home, PATH: '/usr/bin:/bin' },
      encoding: 'utf8',
    });
    expect(out.status, out.stderr).toBe(0);
    const lines = out.stdout.trim().split('\n');
    const dir = lines[lines.length - 1] ?? '';
    const m = /^job key dev-setup-smoke-(\d{12}), expires (\S+)$/.exec(
      lines[0] ?? ''
    );
    expect(m, out.stdout).not.toBeNull();
    const [, stamp = '', expires = ''] = m ?? [];
    expect(path.dirname(dir)).toBe(path.join(home, 'txe-dev-setup-smoke'));
    const lifetime = Date.parse(expires) - before;
    expect(lifetime).toBeGreaterThan(3 * 3600_000 - 120_000);
    expect(lifetime).toBeLessThanOrEqual(3 * 3600_000);
    expect(readFileSync(path.join(dir, 'job.yaml'), 'utf8')).toBe(
      SMOKE_JOB_TEMPLATE.split('{{STAMP}}')
        .join(stamp)
        .split('{{EXPIRES_AT}}')
        .join(expires)
    );
    expect(readFileSync(path.join(dir, 'run.sh'), 'utf8')).toBe(SMOKE_SCRIPT);
    expect(statSync(path.join(dir, 'run.sh')).mode & 0o777).toBe(0o755);
    // Nothing is written where the shell started.
    expect(readdirSync(cwd)).toEqual([]);
  });

  // When the directory cannot be made, nothing is written elsewhere and the
  // shell is not exited.
  it('writes nothing elsewhere when the directory cannot be made', () => {
    const home = mkdtempSync(path.join(tmpdir(), 'dev-setup-smoke-'));
    dirs.push(home);
    writeFileSync(
      path.join(home, 'txe-dev-setup-smoke'),
      'a file, not a directory'
    );
    const cwd = mkdtempSync(path.join(tmpdir(), 'dev-setup-cwd-'));
    dirs.push(cwd);
    const out = spawnSync(
      'sh',
      ['-c', smokeCommands().create + '\necho still-here'],
      {
        cwd,
        env: { HOME: home, PATH: '/usr/bin:/bin' },
        encoding: 'utf8',
      }
    );
    expect(out.stdout).toContain('still-here');
    expect(readdirSync(cwd)).toEqual([]);
  });

  it('registers only on the step that says so', () => {
    const smoke = smokeCommands();
    expect(smoke.create).not.toContain('dagu');
    expect(smoke.dryRun).toContain('--dry-run');
    expect(smoke.register).not.toContain('--dry-run');
  });
});
