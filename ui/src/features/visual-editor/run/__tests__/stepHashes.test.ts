// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { hashText, stepHashes } from '../stepHashes';

const SPEC = `type: graph
steps:
  - id: slow
    name: slow
    run: echo slow
  - id: middle
    name: middle
    depends: [slow]
    run: echo "middle \${steps.slow.outputs.data}"
  - id: use
    name: use
    depends: [middle]
    run: echo use
  - id: other
    name: other
    run: echo other
`;

describe('hashText', () => {
  it('gives equal text the same hash and other text another', () => {
    expect(hashText('a')).toBe(hashText('a'));
    expect(hashText('a')).not.toBe(hashText('b'));
  });
});

describe('stepHashes', () => {
  it('hashes each named step', () => {
    const hashes = stepHashes(SPEC);
    expect([...hashes.keys()]).toEqual(['slow', 'middle', 'use', 'other']);
    expect(new Set(hashes.values()).size).toBe(4);
  });

  it('does not change with a comment or spacing', () => {
    const noisy = SPEC.replace(
      'run: echo slow',
      'run:   echo slow   # the slow step'
    );
    expect(stepHashes(noisy)).toEqual(stepHashes(SPEC));
  });

  it('changes for the step that changed and for the steps that need it', () => {
    const before = stepHashes(SPEC);
    const after = stepHashes(SPEC.replace('echo slow', 'echo slower'));
    expect(after.get('slow')).not.toBe(before.get('slow'));
    // middle depends on slow, and use depends on middle.
    expect(after.get('middle')).not.toBe(before.get('middle'));
    expect(after.get('use')).not.toBe(before.get('use'));
    expect(after.get('other')).toBe(before.get('other'));
  });

  it('keeps the steps before an edited step the same', () => {
    const before = stepHashes(SPEC);
    const after = stepHashes(SPEC.replace('echo use', 'echo use2'));
    expect(after.get('use')).not.toBe(before.get('use'));
    expect(after.get('slow')).toBe(before.get('slow'));
    expect(after.get('middle')).toBe(before.get('middle'));
  });

  it('follows a reference to an output when the step has no depends', () => {
    const spec = `steps:
  - id: a
    name: a
    run: echo a
  - id: b
    name: b
    run: echo \${steps.a.outputs.x}
`;
    const before = stepHashes(spec);
    const after = stepHashes(spec.replace('echo a', 'echo A'));
    expect(after.get('b')).not.toBe(before.get('b'));
  });

  it('follows the step before it in a chain', () => {
    const spec = `type: chain
steps:
  - name: a
    run: echo a
  - name: b
    run: echo b
`;
    const before = stepHashes(spec);
    const after = stepHashes(spec.replace('echo a', 'echo A'));
    expect(after.get('b')).not.toBe(before.get('b'));
  });

  // A chain step that names dependencies of its own still depends on the
  // step before it: the builder adds that edge whatever depends says.
  it('follows the step before it in a chain even with explicit depends', () => {
    const spec = `type: chain
steps:
  - name: a
    run: echo a
  - name: b
    run: echo b
  - name: c
    depends: [a]
    run: echo c
`;
    const before = stepHashes(spec);
    const after = stepHashes(spec.replace('echo b', 'echo B'));
    expect(after.get('c')).not.toBe(before.get('c'));
  });

  // A chain step with no name or id is still the step before the next one.
  it('follows a step with no name in a chain', () => {
    const spec = `type: chain
steps:
  - name: a
    run: echo a
  - run: echo middle
  - name: c
    run: echo c
`;
    const before = stepHashes(spec);
    const after = stepHashes(spec.replace('echo middle', 'echo MIDDLE'));
    expect([...before.keys()]).toEqual(['a', 'c']);
    expect(after.get('a')).toBe(before.get('a'));
    expect(after.get('c')).not.toBe(before.get('c'));
  });

  // The server makes each route target depend on its router.
  it('follows the router of a route target', () => {
    const spec = `steps:
  - name: route
    action: router.route
    with:
      value: \${CODE}
      routes:
        ok: [handle]
  - name: handle
    run: echo handle
`;
    const before = stepHashes(spec);
    const after = stepHashes(spec.replace('ok: [handle]', 'done: [handle]'));
    expect(after.get('handle')).not.toBe(before.get('handle'));
  });

  // The steps of a parallel group follow the entry before the group, not
  // each other, and the next step follows every step of the group.
  it('follows the entry before a parallel group in a chain', () => {
    const spec = `type: chain
steps:
  - name: a
    run: echo a
  - name: b
    run: echo b
  - name: c
    run: echo c
`;
    const grouped = `type: chain
steps:
  - - name: a
      run: echo a
    - name: b
      run: echo b
  - name: c
    run: echo c
`;
    const before = stepHashes(spec);
    expect(stepHashes(grouped).get('b')).not.toBe(before.get('b'));
    const edited = stepHashes(grouped.replace('echo a', 'echo A'));
    expect(edited.get('b')).toBe(stepHashes(grouped).get('b'));
    expect(edited.get('c')).not.toBe(stepHashes(grouped).get('c'));
  });

  // A step can run a sub-DAG that a later document defines.
  it('changes every step when a later document changes', () => {
    const child = (run: string) =>
      `${SPEC}---\nname: child\nsteps:\n  - name: work\n    run: ${run}\n`;
    const before = stepHashes(child('echo a'));
    const after = stepHashes(child('echo b'));
    for (const name of before.keys()) {
      expect(after.get(name)).not.toBe(before.get(name));
    }
  });

  it('gives one result to the calls with the same text', () => {
    expect(stepHashes(SPEC)).toBe(stepHashes(SPEC));
  });

  it('changes every step when a top-level key changes', () => {
    const before = stepHashes(SPEC);
    const after = stepHashes(`env:\n  - X: 1\n${SPEC}`);
    for (const name of before.keys()) {
      expect(after.get(name)).not.toBe(before.get(name));
    }
  });

  it('gives no hash for a text that cannot be read', () => {
    expect(stepHashes('steps: [').size).toBe(0);
  });
});

// The hashes and diffRunSpec share one head (headOf): a handler that runs
// before or among the steps changes every hash, an end-of-run handler none.
describe('stepHashes and the handlers', () => {
  const withHandler = (handler: string, command: string) =>
    `${SPEC}handler_on:\n  ${handler}:\n    run: ${command}\n`;

  it('changes every hash when the init handler changes', () => {
    const before = stepHashes(withHandler('init', 'echo prepare > input'));
    const after = stepHashes(withHandler('init', 'echo other > input'));
    expect(before.size).toBeGreaterThan(0);
    for (const [name, hash] of before)
      expect(after.get(name), name).not.toBe(hash);
  });

  it('keeps every hash when an end-of-run handler changes', () => {
    const before = stepHashes(withHandler('success', 'echo done'));
    const after = stepHashes(withHandler('success', 'echo finished'));
    expect([...after]).toEqual([...before]);
  });
});

// `transformRouterSteps` accepts a router target by name or by id.
describe('stepHashes and router targets', () => {
  const routed = (route: string) => `type: graph
steps:
  - id: decide
    name: decide
    action: router.route
    with:
      value: \${CODE}
      routes:
        ${route}: [target_id]
  - id: target_id
    name: target
    run: echo target
  - id: after
    name: after
    depends: [target]
    run: echo after
`;

  it('changes the hash of a target named by its id, and of what follows it', () => {
    const before = stepHashes(routed('ok'));
    const after = stepHashes(routed('done'));
    expect(after.get('decide')).not.toBe(before.get('decide'));
    expect(after.get('target')).not.toBe(before.get('target'));
    expect(after.get('after')).not.toBe(before.get('after'));
  });
});

// The server resolves a step reference by name or id (`transformRouterSteps`,
// the depends and output references). Every lookup here goes through
// `lookup` or the router's own index: a name-only lookup fails this check.
describe('stepHashes reference lookups', () => {
  it('resolves every reference by name or id', () => {
    const source = readFileSync(
      path.resolve('src/features/visual-editor/run/stepHashes.ts'),
      'utf8'
    );
    const lookups = source.match(/\b(byName|byId)\.get\(/g) ?? [];
    expect(lookups, 'only `lookup` reads byName and byId').toHaveLength(2);
    expect(source).toMatch(
      /const lookup = \(ref: string\): Item \| undefined =>\s*byName\.get\(ref\) \?\? byId\.get\(ref\);/
    );
  });
});
