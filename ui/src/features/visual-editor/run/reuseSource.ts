// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import type { components } from '@/api/v1/schema';
import { NodeStatus } from '@/api/v1/schema';
import { parseParams } from '@/lib/parseParams';
import { fromDetails } from './inputProvenance';
import type { CacheEntries, CacheEntry } from './outputCache';
import type { RunSpecDiff } from './runSpecDiff';
import { isReusedNode, isRunActive } from './stepRunInfo';

type DAGRunDetails = components['schemas']['DAGRunDetails'];

/** What the choice of a source needs of a run. */
export type ReuseRun = Pick<DAGRunDetails, 'dagRunId' | 'status'> &
  Partial<
    Pick<
      DAGRunDetails,
      | 'nodes'
      | 'params'
      | 'paramsList'
      | 'labels'
      | 'startedAt'
      | 'finishedAt'
      | 'reusedInputs'
    >
  >;

/** Steps that a step needs, by step name. */
export type StepNeeds = ReadonlyMap<string, readonly string[]>;

/** The needs of each step: `depends` and the steps that it reads from. */
export function stepNeeds(
  steps:
    | ReadonlyArray<{
        name: string;
        depends?: string[] | null;
        inferredDepends?: string[] | null;
      }>
    | undefined
    | null
): StepNeeds {
  return new Map(
    (steps ?? []).map((s) => [
      s.name,
      [...(s.depends ?? []), ...(s.inferredDepends ?? [])],
    ])
  );
}

/**
 * The previous steps that can behave differently from the source run: the
 * steps that changed (or that the live text renamed, removed or added), and the steps that need them (also through other
 * steps). When the head changed, all previous steps. The result keeps the
 * order of `previous`.
 */
export function staleUpstream(p: {
  diff: RunSpecDiff;
  previous: readonly string[];
  deps: StepNeeds;
  /**
   * Steps whose outputs in the run were reused although the step had
   * changed (staleReusedInputs): the run's own definition matches them, but
   * their values do not, and nothing downstream of them is fresh either.
   */
  staleInputs?: readonly string[];
}): string[] {
  if (p.diff.headChanged) return [...p.previous];
  const previous = new Set(p.previous);
  // A step that the live text renamed, removed or added is not the step of
  // the run either.
  const touched = (name: string) =>
    p.diff.changed.has(name) ||
    p.diff.removedFromLive.has(name) ||
    p.diff.addedInLive.has(name);
  const stale = new Set([
    ...p.previous.filter(touched),
    ...(p.staleInputs ?? []),
  ]);
  for (let grew = true; grew; ) {
    grew = false;
    for (const name of previous) {
      if (stale.has(name)) continue;
      if ((p.deps.get(name) ?? []).some((dep) => stale.has(dep))) {
        stale.add(name);
        grew = true;
      }
    }
  }
  return p.previous.filter((name) => stale.has(name));
}

/**
 * The steps that a run reused whose outputs are not known to be fresh for
 * the run's own definition. The run's definition shows a reused step as it
 * is now, so comparing definitions alone would take the outputs the run
 * gives it, and every step that consumed them, for fresh.
 *
 * A reused step is fresh only when the server's record names it
 * (`reusedInputs`) and no `dagu.input` label marks it stale. Every other
 * reused node is unverified and counts as stale: one recorded stale, one
 * from a server or a run that kept no record (only `dagu.outputs-from`, or
 * nothing), and a plain skip, which the node alone cannot tell from a
 * reused one. Unknown provenance never makes automatic reuse look fresh.
 *
 * The cache capture is stricter still (`upstreamRanInRun`): it keeps a
 * step's outputs only when every step upstream of it ran in the run.
 */
export function staleReusedInputs(run: ReuseRun | null): string[] {
  if (!run) return [];
  const recorded = fromDetails(run);
  return (run.nodes ?? [])
    .filter(isReusedNode)
    .map((node) => node.step.name)
    .filter((name) => {
      const record = recorded?.get(name);
      return !record || record.stale;
    });
}

/**
 * True when the run holds a state of the step that a new run can copy, as
 * the server decides it (`transform.Reusable`): the step succeeded, or the
 * run itself carried it from another run. A skipped node holds outputs only
 * when the server's record names it as reused (`reusedInputs`): a step that
 * its precondition skipped has a finish time too, and the server copies
 * nothing of it, so the step would run without its inputs. A run that kept
 * no record (an older server) is not taken at its word: such a skip counts
 * as missing, and the step runs again.
 */
export function runHoldsOutputs(run: ReuseRun, step: string): boolean {
  const node = (run.nodes ?? []).find((n) => n.step.name === step);
  if (!node) return false;
  if (
    node.status === NodeStatus.Success ||
    node.status === NodeStatus.PartialSuccess
  ) {
    return true;
  }
  return isReusedNode(node) && (fromDetails(run)?.has(step) ?? false);
}

/** The previous steps that the run has no reusable state for. */
export function missingIn(
  run: ReuseRun | null,
  previous: readonly string[]
): string[] {
  if (!run) return [];
  return previous.filter((name) => !runHoldsOutputs(run, name));
}

// isRunActive reads only the status.
/** True while the run can still change: a source must not be such a run. */
export function isActive(run: ReuseRun): boolean {
  return isRunActive(run as DAGRunDetails);
}

/** True when the nodes of the run hold every step in `reads`. */
function nodesHold(run: ReuseRun, reads: readonly string[]): boolean {
  return missingIn(run, reads).length === 0;
}

export interface ReusePick {
  /** The run that "Step only" and "Changed steps" copy outputs from. */
  source: ReuseRun | null;
  /** The active run that the step waits for, when it has no source yet. */
  waitingFor: string | null;
}

/**
 * Chooses the run to copy outputs from, in this order:
 * 1. the followed upstream run, when it is finished (when it is active, the
 *    step waits for it);
 * 2. the selected run, when it is finished and holds every read;
 * 3. the newest finished run of `history` (newest first) that holds every
 *    read;
 * 4. none. When an active run of the history holds every read, the step
 *    waits for it.
 * An active run is never a source: the server refuses it. `holds` confirms a
 * candidate that the nodes show as complete, for example by a request.
 */
export async function pickReuseSource(p: {
  followedUpstream: ReuseRun | null;
  selected: ReuseRun | null;
  history: readonly ReuseRun[];
  reads: readonly string[];
  holds: (run: ReuseRun) => Promise<boolean>;
}): Promise<ReusePick> {
  const { followedUpstream, selected, history, reads, holds } = p;
  if (followedUpstream) {
    return isActive(followedUpstream)
      ? { source: null, waitingFor: followedUpstream.dagRunId }
      : { source: followedUpstream, waitingFor: null };
  }
  const tried = new Set<string>();
  const qualifies = async (run: ReuseRun): Promise<boolean> => {
    if (tried.has(run.dagRunId)) return false;
    tried.add(run.dagRunId);
    return !isActive(run) && nodesHold(run, reads) && (await holds(run));
  };
  if (selected && (await qualifies(selected))) {
    return { source: selected, waitingFor: null };
  }
  for (const run of history) {
    if (await qualifies(run)) return { source: run, waitingFor: null };
  }
  const active = [...(selected ? [selected] : []), ...history].find(
    (run) => isActive(run) && nodesHold(run, reads)
  );
  return { source: null, waitingFor: active ? active.dagRunId : null };
}

export interface RunPlan {
  /** Run the step alone; the other steps copy their outputs. */
  only: string[];
  /** Run the changed and missing previous steps, then the step. */
  changed: string[];
  /** Run all previous steps, then the step. */
  full: string[];
}

/**
 * The `steps` of each choice of the step run. `order` is the dependency order
 * of the steps; a name that it does not list goes last.
 */
export function planRun(p: {
  previous: readonly string[];
  stale: readonly string[];
  missing: readonly string[];
  step: string;
  order: readonly string[];
}): RunPlan {
  const { step } = p;
  const rank = (name: string) => {
    const at = p.order.indexOf(name);
    return at === -1 ? p.order.length : at;
  };
  const redo = new Set([...p.stale, ...p.missing]);
  redo.delete(step);
  const sorted = [...redo]
    .map((name, i) => ({ name, i }))
    .sort((a, b) => rank(a.name) - rank(b.name) || a.i - b.i)
    .map((entry) => entry.name);
  return {
    only: [step],
    changed: [...sorted, step],
    full: [...p.previous.filter((name) => name !== step), step],
  };
}

/**
 * Whether the run that a cache entry names can still give the step: 'ok' when
 * the run exists and its node of the step succeeded, 'gone' when it does not
 * (removed, or a test run that expired), 'active' while the run has not
 * finished (the server reuses outputs of a finished run only) and 'checking'
 * while the server has not answered.
 */
export type RunCheck = 'ok' | 'gone' | 'active' | 'checking';

/** What the cache of the browser gives to the previous steps of a step run. */
export interface CacheCover {
  /** `stale` without the steps that the cache covers. */
  stale: string[];
  /**
   * The previous steps that neither the source run nor the cache covers.
   * Without a source run, it lists them only when the cache covers a step.
   */
  missing: string[];
  /**
   * Steps that a fresh entry covers: the hash equals the current one and the
   * run that the entry names can still give the step.
   */
  cached: string[];
  /** The run (and capture time) that each covered step is read from. */
  runs: Record<string, { runId: string; capturedAt: number }>;
  /** Steps with a fresh entry whose run is gone: no longer available. */
  gone: string[];
  /** True while a run that an entry names has not been checked. */
  checking: boolean;
  /** The oldest capture time of the covered steps; null when none is covered. */
  capturedAt: number | null;
  /** The capture time of each covered step. */
  times: Record<string, number>;
}

/**
 * Covers the previous steps from the cache, for the steps that the source run
 * does not cover: a step that the source run holds and that did not change
 * takes its outputs from that run, never from the cache. An entry covers a
 * step when its hash is the current hash of the step, which includes the
 * steps that it needs, and its run can still give the step (`check`); a stale
 * entry, or one whose run is gone, covers nothing. `hashes` is null while the
 * current definition is not known: then nothing is covered.
 */
export function coverFromCache(p: {
  previous: readonly string[];
  stale: readonly string[];
  missing: readonly string[];
  hasSource: boolean;
  entries: CacheEntries;
  hashes: ReadonlyMap<string, string> | null;
  check: (step: string, entry: CacheEntry) => RunCheck;
}): CacheCover {
  const cached: string[] = [];
  const gone: string[] = [];
  const runs: Record<string, { runId: string; capturedAt: number }> = {};
  const times: Record<string, number> = {};
  let capturedAt: number | null = null;
  let checking = false;
  // With a source run, only the steps that it cannot give look at the cache.
  const open = new Set([...p.stale, ...p.missing]);
  for (const name of p.previous) {
    if (p.hasSource && !open.has(name)) continue;
    const entry = p.entries[name];
    if (!entry || p.hashes?.get(name) !== entry.stepHash) continue;
    const state = p.check(name, entry);
    if (state === 'checking') {
      checking = true;
      continue;
    }
    if (state === 'gone') {
      gone.push(name);
      continue;
    }
    if (state === 'active') continue;
    cached.push(name);
    capturedAt =
      capturedAt === null
        ? entry.capturedAt
        : Math.min(capturedAt, entry.capturedAt);
    runs[name] = { runId: entry.runId, capturedAt: entry.capturedAt };
    times[name] = entry.capturedAt;
  }
  const covered = new Set(cached);
  const notCovered = (names: readonly string[]) =>
    names.filter((name) => !covered.has(name));
  const missing = p.hasSource
    ? notCovered(p.missing)
    : covered.size > 0
      ? notCovered(p.previous)
      : [];
  return {
    stale: notCovered(p.stale),
    missing,
    cached,
    runs,
    gone,
    checking,
    capturedAt,
    times,
  };
}

export type RunChoice = 'only' | 'changed' | 'run';

/**
 * The button that the step run dialog makes the default: "Step only" when
 * every previous step is covered (by the source run or the cache) and
 * fresh, "Changed steps" when a previous step changed or is missing, and
 * "Run" when nothing covers a previous step. `covered` counts the steps that
 * the cache covers.
 */
export function defaultChoice(p: {
  source: unknown;
  stale: readonly string[];
  missing: readonly string[];
  covered?: number;
}): RunChoice {
  if (!p.source && !(p.covered && p.covered > 0)) return 'run';
  return p.stale.length > 0 || p.missing.length > 0 ? 'changed' : 'only';
}

/**
 * True when the parameters of the source run differ from the defaults of the
 * workflow. A new step run uses the defaults.
 *
 * The run's parameters are compared as the list the run received
 * (`paramsList`, one `NAME=value` per item), item by item, with the defaults
 * parsed exactly; quotes do not count, and every character of a value does.
 * A run's joined listing (`params`) is unquoted, so `A="1 B=2"` and
 * `A=1 B=2`, or `A="a  b"` and `A="a b"`, read alike there; it is never used
 * (TXE-5923). A run whose list is unknown, as from a server or record that
 * does not send it, counts as different: that costs a reuse and never gives a
 * wrong one.
 */
export function paramsDiffer(
  runParamsList: readonly string[] | null | undefined,
  defaults: string | null | undefined
): boolean {
  if (!runParamsList) return true;
  const wanted = parseParams(defaults ?? '').map((param) =>
    param.Name ? `${param.Name}=${param.Value}` : param.Value
  );
  return (
    wanted.length !== runParamsList.length ||
    wanted.some((item, i) => item !== runParamsList[i])
  );
}
