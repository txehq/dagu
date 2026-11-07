// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it, vi } from 'vitest';
import {
  NodeStatus,
  ReusedInputVia,
  Status,
  type components,
} from '@/api/v1/schema';
import {
  coverFromCache,
  defaultChoice,
  missingIn,
  paramsDiffer,
  runHoldsOutputs,
  pickReuseSource,
  planRun,
  staleReusedInputs,
  staleUpstream,
  stepNeeds,
  type ReuseRun,
} from '../reuseSource';
import { inputLabel } from '../inputProvenance';
import type { CacheEntry } from '../outputCache';
import type { RunSpecDiff } from '../runSpecDiff';

type Node = components['schemas']['Node'];

function node(name: string, status: NodeStatus = NodeStatus.Success): Node {
  return {
    step: { name },
    status,
    finishedAt: '2026-10-01T00:00:05Z',
    doneCount: 1,
  } as Node;
}

function runOf(
  id: string,
  status: Status,
  nodes: Node[] = [node('a'), node('b')],
  params?: string
): ReuseRun {
  return {
    dagRunId: id,
    status,
    nodes,
    ...(params !== undefined ? { params } : {}),
  };
}

function diffOf(p: Partial<RunSpecDiff> = {}): RunSpecDiff {
  return {
    headChanged: false,
    changed: new Set(),
    removedFromLive: new Set(),
    addedInLive: new Set(),
    ...p,
  };
}

const yes = () => Promise.resolve(true);

describe('pickReuseSource', () => {
  const reads = ['a', 'b'];

  it('skips an active run and picks the newest finished run that holds every read', async () => {
    const history = [
      runOf('active', Status.Running),
      runOf('partial', Status.Failed, [
        node('a'),
        node('b', NodeStatus.Failed),
      ]),
      runOf('good', Status.Success),
      runOf('older', Status.Success),
    ];
    const pick = await pickReuseSource({
      followedUpstream: null,
      selected: null,
      history,
      reads,
      holds: yes,
    });
    expect(pick.source?.dagRunId).toBe('good');
    expect(pick.waitingFor).toBeNull();
  });

  it('prefers the selected run when it qualifies', async () => {
    const selected = runOf('selected', Status.Success);
    const pick = await pickReuseSource({
      followedUpstream: null,
      selected,
      history: [runOf('newer', Status.Success), selected],
      reads,
      holds: yes,
    });
    expect(pick.source?.dagRunId).toBe('selected');
  });

  it('takes the newest run when the selected run does not qualify', async () => {
    const pick = await pickReuseSource({
      followedUpstream: null,
      selected: runOf('selected', Status.Failed, [node('a')]),
      history: [runOf('newer', Status.Success)],
      reads,
      holds: yes,
    });
    expect(pick.source?.dagRunId).toBe('newer');
  });

  it('gives no source when no run qualifies', async () => {
    const pick = await pickReuseSource({
      followedUpstream: null,
      selected: runOf('selected', Status.Failed, []),
      history: [runOf('x', Status.Success, [node('a')])],
      reads,
      holds: yes,
    });
    expect(pick).toEqual({ source: null, waitingFor: null });
  });

  it('skips a run that the outputs check refuses', async () => {
    const holds = vi.fn(async (r: ReuseRun) => r.dagRunId !== 'first');
    const pick = await pickReuseSource({
      followedUpstream: null,
      selected: null,
      history: [
        runOf('first', Status.Success),
        runOf('second', Status.Success),
      ],
      reads,
      holds,
    });
    expect(pick.source?.dagRunId).toBe('second');
    expect(holds).toHaveBeenCalledTimes(2);
  });

  it('waits for an active run when only an active run qualifies', async () => {
    const pick = await pickReuseSource({
      followedUpstream: null,
      selected: null,
      history: [runOf('active', Status.Running)],
      reads,
      holds: yes,
    });
    expect(pick).toEqual({ source: null, waitingFor: 'active' });
  });

  it('uses the finished followed run without a check', async () => {
    const holds = vi.fn(yes);
    const followed = runOf('followed', Status.Success, []);
    const pick = await pickReuseSource({
      followedUpstream: followed,
      selected: runOf('selected', Status.Success),
      history: [runOf('newer', Status.Success)],
      reads,
      holds,
    });
    expect(pick.source).toBe(followed);
    expect(holds).not.toHaveBeenCalled();
  });

  it('waits for an active followed run', async () => {
    const pick = await pickReuseSource({
      followedUpstream: runOf('followed', Status.Running, []),
      selected: runOf('selected', Status.Success),
      history: [runOf('newer', Status.Success)],
      reads,
      holds: yes,
    });
    expect(pick).toEqual({ source: null, waitingFor: 'followed' });
  });

  it('counts a reused node as holding its outputs', async () => {
    const reused = {
      ...node('a', NodeStatus.Skipped),
      doneCount: 1,
    } as Node;
    const pick = await pickReuseSource({
      followedUpstream: null,
      selected: null,
      history: [
        {
          ...runOf('chain', Status.Success, [reused, node('b')]),
          reusedInputs: [{ step: 'a', runId: 'old', via: ReusedInputVia.run }],
        },
      ],
      reads,
      holds: yes,
    });
    expect(pick.source?.dagRunId).toBe('chain');
  });

  // A precondition skip has a finish time too, and the server copies nothing
  // of it (transform.Reusable): only the server's record of a reuse makes a
  // skipped node hold outputs. A run that kept no record is not taken at its
  // word.
  it('does not count a skip the server did not record as a reuse', async () => {
    const skipped = {
      ...node('a', NodeStatus.Skipped),
      doneCount: 1,
    } as Node;
    const run = runOf('skipped', Status.Success, [skipped, node('b')]);
    expect(missingIn(run, ['a', 'b'])).toEqual(['a']);
    expect(runHoldsOutputs(run, 'a')).toBe(false);
    expect(runHoldsOutputs(run, 'b')).toBe(true);
    expect(runHoldsOutputs(run, 'absent')).toBe(false);
    const pick = await pickReuseSource({
      followedUpstream: null,
      selected: null,
      history: [run],
      reads,
      holds: yes,
    });
    expect(pick.source).toBeNull();
  });
});

// A -> B -> C. A was edited, and B was run on its own with A's old outputs:
// that run's definition shows the edited A, so only the run's provenance can
// say whether A's values are fresh. A reused step is fresh only when the
// server's record names it and no label marks it stale; any other reused
// node is unverified and counts as stale, so unknown provenance never makes
// automatic reuse look fresh.
describe('a source run that reused a step', () => {
  const deps = stepNeeds([
    { name: 'a' },
    { name: 'b', depends: ['a'] },
    { name: 'c', depends: ['b'] },
  ]);
  const staleLabel = inputLabel({
    step: 'a',
    source: 'run',
    runId: 'old',
    stale: true,
    capturedAt: 1_700_000_000_000,
  }) as string;
  const record = [
    { step: 'a', runId: 'old', via: ReusedInputVia.run },
  ] as ReuseRun['reusedInputs'];
  const sourceRun = (
    p: { labels?: string[]; reusedInputs?: ReuseRun['reusedInputs'] } = {}
  ): ReuseRun => ({
    ...runOf('b-only', Status.Success, [
      node('a', NodeStatus.Skipped),
      node('b'),
    ]),
    ...p,
  });

  it.each<
    [
      string,
      { labels?: string[]; reusedInputs?: ReuseRun['reusedInputs'] },
      string[],
    ]
  >([
    [
      'recorded by the server and not marked stale',
      { reusedInputs: record },
      [],
    ],
    [
      'recorded and marked stale by its label',
      { reusedInputs: record, labels: [staleLabel] },
      ['a'],
    ],
    [
      'marked stale by a label of a run with no record',
      { labels: [staleLabel] },
      ['a'],
    ],
    [
      'named only by the old outputs-from label',
      { labels: ['dagu.outputs-from=old'] },
      ['a'],
    ],
    ['with no provenance at all, as a plain skip', {}, ['a']],
  ])('a reused step %s', (_, p, want) => {
    expect(staleReusedInputs(sourceRun(p))).toEqual(want);
  });

  it('names no step that ran, whatever its labels say', () => {
    const run: ReuseRun = {
      ...runOf('retried', Status.Success, [node('a'), node('b')]),
      labels: [staleLabel],
    };
    expect(staleReusedInputs(run)).toEqual([]);
    expect(staleReusedInputs(null)).toEqual([]);
  });

  it('marks an unverified input and everything downstream of it, though the definitions match', () => {
    expect(
      staleUpstream({
        diff: diffOf(),
        previous: ['a', 'b'],
        deps,
        staleInputs: staleReusedInputs(sourceRun({ labels: [staleLabel] })),
      })
    ).toEqual(['a', 'b']);
  });

  it('keeps a source whose reused steps the server records as fresh', () => {
    expect(
      staleUpstream({
        diff: diffOf(),
        previous: ['a', 'b'],
        deps,
        staleInputs: staleReusedInputs(sourceRun({ reusedInputs: record })),
      })
    ).toEqual([]);
  });

  // The steps' dependencies are the server's, chain, parallel and router
  // edges included: a stale input reaches every step after it along them.
  it('propagates through a parallel group and a router target', () => {
    const graph = stepNeeds([
      { name: 'a' },
      { name: 'p1', depends: ['a'] },
      { name: 'p2', depends: ['a'] },
      { name: 'join', depends: ['p1', 'p2'] },
      { name: 'route', depends: ['join'] },
      { name: 'target', depends: ['route'] },
      { name: 'apart' },
    ]);
    expect(
      staleUpstream({
        diff: diffOf(),
        previous: ['a', 'p1', 'p2', 'join', 'route', 'target', 'apart'],
        deps: graph,
        staleInputs: ['a'],
      })
    ).toEqual(['a', 'p1', 'p2', 'join', 'route', 'target']);
  });
});

describe('staleUpstream', () => {
  const deps = stepNeeds([
    { name: 'a' },
    { name: 'b', depends: ['a'] },
    { name: 'c', depends: ['b'] },
    { name: 'd', inferredDepends: ['c'] },
    { name: 'x' },
  ]);
  const previous = ['a', 'b', 'c', 'd', 'x'];

  it('is empty when nothing changed', () => {
    expect(staleUpstream({ diff: diffOf(), previous, deps })).toEqual([]);
  });

  it('marks a changed step and the steps downstream of it', () => {
    expect(
      staleUpstream({
        diff: diffOf({ changed: new Set(['b']) }),
        previous,
        deps,
      })
    ).toEqual(['b', 'c', 'd']);
  });

  it('marks all previous steps when the head changed', () => {
    expect(
      staleUpstream({ diff: diffOf({ headChanged: true }), previous, deps })
    ).toEqual(previous);
  });

  it('marks a step that the live text renamed away', () => {
    expect(
      staleUpstream({
        diff: diffOf({ removedFromLive: new Set(['x']) }),
        previous,
        deps,
      })
    ).toEqual(['x']);
  });
});

describe('missingIn', () => {
  it('lists the steps without a reusable node', () => {
    const run = runOf('r', Status.Failed, [
      node('a'),
      node('b', NodeStatus.Failed),
    ]);
    expect(missingIn(run, ['a', 'b', 'c'])).toEqual(['b', 'c']);
    expect(missingIn(null, ['a'])).toEqual([]);
  });

  // The server reuses a partially succeeded node, for example a call step.
  it('counts a partially succeeded node as reusable', () => {
    const run = runOf('r', Status.PartialSuccess, [
      node('a', NodeStatus.PartialSuccess),
    ]);
    expect(missingIn(run, ['a'])).toEqual([]);
  });
});

describe('planRun', () => {
  it('builds the steps of the three choices in dependency order', () => {
    const plan = planRun({
      previous: ['a', 'b', 'c'],
      stale: ['c'],
      missing: ['a'],
      step: 'd',
      order: ['a', 'b', 'c'],
    });
    expect(plan.only).toEqual(['d']);
    expect(plan.changed).toEqual(['a', 'c', 'd']);
    expect(plan.full).toEqual(['a', 'b', 'c', 'd']);
  });

  it('lists a step once and never lists the step before the end', () => {
    const plan = planRun({
      previous: ['a'],
      stale: ['a', 'd'],
      missing: ['a'],
      step: 'd',
      order: ['a'],
    });
    expect(plan.changed).toEqual(['a', 'd']);
  });
});

describe('defaultChoice', () => {
  it('chooses the button for the state of the source', () => {
    const source = { dagRunId: 'r' };
    expect(defaultChoice({ source: null, stale: [], missing: [] })).toBe('run');
    expect(defaultChoice({ source, stale: [], missing: [] })).toBe('only');
    expect(defaultChoice({ source, stale: ['a'], missing: [] })).toBe(
      'changed'
    );
    expect(defaultChoice({ source, stale: [], missing: ['a'] })).toBe(
      'changed'
    );
  });
});

function entry(p: Partial<CacheEntry> = {}): CacheEntry {
  return {
    values: { out: 'v' },
    runId: 'r1',
    capturedAt: 1000,
    stepHash: 'h-a',
    ...p,
  };
}

const ok = () => 'ok' as const;

describe('coverFromCache', () => {
  const previous = ['a', 'b'];
  const hashes = new Map([
    ['a', 'h-a'],
    ['b', 'h-b'],
  ]);

  it('covers a step whose entry hash equals the current hash', () => {
    const cover = coverFromCache({
      previous,
      stale: ['a', 'b'],
      missing: [],
      hasSource: true,
      entries: { a: entry() },
      hashes,
      check: ok,
    });
    expect(cover.cached).toEqual(['a']);
    expect(cover.stale).toEqual(['b']);
    expect(Object.keys(cover.runs)).toEqual(['a']);
    expect(cover.capturedAt).toBe(1000);
  });

  // Every cached value is sent with the run that it was read from.
  it('names the run and the time of each covered step', () => {
    const cover = coverFromCache({
      previous,
      stale: [],
      missing: [],
      hasSource: false,
      entries: {
        a: entry({ runId: 'run-a', capturedAt: 3000 }),
        b: entry({ stepHash: 'h-b', runId: 'run-b', capturedAt: 2000 }),
      },
      hashes,
      check: ok,
    });
    expect(cover.runs).toEqual({
      a: { runId: 'run-a', capturedAt: 3000 },
      b: { runId: 'run-b', capturedAt: 2000 },
    });
  });

  it('leaves a step to the source run when the run holds it and it did not change', () => {
    const cover = coverFromCache({
      previous,
      stale: [],
      missing: ['b'],
      hasSource: true,
      entries: { a: entry(), b: entry({ stepHash: 'h-b' }) },
      hashes,
      check: ok,
    });
    expect(cover.cached).toEqual(['b']);
    expect(Object.keys(cover.runs)).toEqual(['b']);
    expect(cover.missing).toEqual([]);
  });

  it('leaves a stale entry as it was: it covers nothing', () => {
    const cover = coverFromCache({
      previous,
      stale: ['a'],
      missing: ['b'],
      hasSource: true,
      entries: { a: entry({ stepHash: 'old' }) },
      hashes,
      check: ok,
    });
    expect(cover.cached).toEqual([]);
    expect(cover.stale).toEqual(['a']);
    expect(cover.missing).toEqual(['b']);
    expect(cover.runs).toEqual({});
  });

  // A cache entry names a run: it covers the step only while the run exists
  // and holds the step. A step with a run that is gone counts as missing.
  it('does not cover a step whose run is gone, and names it', () => {
    const cover = coverFromCache({
      previous,
      stale: [],
      missing: ['a', 'b'],
      hasSource: true,
      entries: { a: entry(), b: entry({ stepHash: 'h-b', runId: 'r2' }) },
      hashes,
      check: (_step, e) => (e.runId === 'r2' ? 'gone' : 'ok'),
    });
    expect(cover.cached).toEqual(['a']);
    expect(cover.gone).toEqual(['b']);
    expect(cover.missing).toEqual(['b']);
    expect(cover.checking).toBe(false);
  });

  it('waits for a run that is not checked yet', () => {
    const cover = coverFromCache({
      previous,
      stale: [],
      missing: [],
      hasSource: false,
      entries: { a: entry() },
      hashes,
      check: () => 'checking',
    });
    expect(cover.checking).toBe(true);
    expect(cover.cached).toEqual([]);
  });

  it('covers nothing while the definition is not known', () => {
    const cover = coverFromCache({
      previous,
      stale: [],
      missing: [],
      hasSource: false,
      entries: { a: entry(), b: entry() },
      hashes: null,
      check: ok,
    });
    expect(cover.cached).toEqual([]);
    expect(cover.runs).toEqual({});
  });

  it('lists the uncovered steps as missing when no run is the source', () => {
    const cover = coverFromCache({
      previous,
      stale: [],
      missing: [],
      hasSource: false,
      entries: { a: entry() },
      hashes,
      check: ok,
    });
    expect(cover.cached).toEqual(['a']);
    expect(cover.missing).toEqual(['b']);
  });

  it('lists nothing as missing when no run and no entry cover a step', () => {
    const cover = coverFromCache({
      previous,
      stale: [],
      missing: [],
      hasSource: false,
      entries: {},
      hashes,
      check: ok,
    });
    expect(cover.missing).toEqual([]);
  });

  it('keeps the oldest capture time of the covered steps', () => {
    const cover = coverFromCache({
      previous,
      stale: [],
      missing: [],
      hasSource: false,
      entries: {
        a: entry({ capturedAt: 3000 }),
        b: entry({ stepHash: 'h-b', capturedAt: 2000 }),
      },
      hashes,
      check: ok,
    });
    expect(cover.capturedAt).toBe(2000);
    expect(cover.times).toEqual({ a: 3000, b: 2000 });
  });
});

describe('defaultChoice with the cache', () => {
  it('is Step only when the cache covers every previous step and no run exists', () => {
    expect(
      defaultChoice({ source: null, stale: [], missing: [], covered: 2 })
    ).toBe('only');
  });

  it('is Changed steps when the cache covers some steps only', () => {
    expect(
      defaultChoice({ source: null, stale: [], missing: ['b'], covered: 1 })
    ).toBe('changed');
  });

  it('is Run when nothing covers a previous step', () => {
    expect(
      defaultChoice({ source: null, stale: [], missing: [], covered: 0 })
    ).toBe('run');
  });
});

describe('paramsDiffer', () => {
  it('is true for other parameters', () => {
    expect(paramsDiffer(['A=2'], 'A=1')).toBe(true);
    expect(paramsDiffer(['A=1'], undefined)).toBe(true);
  });

  it('treats no parameters as equal', () => {
    expect(paramsDiffer([], '')).toBe(false);
    expect(paramsDiffer([], undefined)).toBe(false);
  });

  // The server quotes each default value; a run's list holds them bare.
  it('reads quoted defaults against the run list', () => {
    expect(paramsDiffer(['A=1', 'MSG=hi there'], 'A="1" MSG="hi there"')).toBe(
      false
    );
    expect(paramsDiffer(['A=2'], 'A="1"')).toBe(true);
  });

  // TXE fork (TXE-5923): the list, not the joined listing, is compared, so
  // neither whitespace inside a value nor where one value ends is lost.
  it('compares every value exactly, and where each one ends', () => {
    expect(paramsDiffer(['A=a  b'], 'A="a b"')).toBe(true);
    expect(paramsDiffer(['A=a b'], 'A="a\\nb"')).toBe(true);
    expect(paramsDiffer(['A=a  b'], 'A="a  b"')).toBe(false);
    expect(paramsDiffer(['A=1', 'B=2'], 'A="1 B=2"')).toBe(true);
    expect(paramsDiffer(['A=1 B=2'], 'A=1 B=2')).toBe(true);
  });

  it('counts an unknown run list as different', () => {
    expect(paramsDiffer(undefined, '')).toBe(true);
    expect(paramsDiffer(null, 'A=1')).toBe(true);
  });
});
