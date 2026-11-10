// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import {
  inputLabel,
  OUTPUTS_FROM_PREFIX,
  STALE_UNRECORDED_LABEL,
  type InputProvenance,
} from './inputProvenance';

export { outputsFromRunId } from './inputProvenance';

// Label that marks every run started from the visual editor.
export const EDITOR_RUN_LABEL = 'dagu.source=editor';

export interface StepRunOptions {
  /** Server names of the steps to run, in order. */
  steps: string[];
  /** The main source: the server carries the outputs and the work directory from it. */
  outputsFromRunId?: string;
  /**
   * The run of each reused previous step that has one of its own, by step
   * name (`outputsFromRuns`). The server reads the outputs from that run. The
   * browser never sends a value: no `outputs` key is ever in a request.
   */
  outputsFromRuns?: Readonly<Record<string, string>>;
  /**
   * The reused previous steps and where their outputs come from. The server
   * keeps the source of each one (`reusedInputs`); only a step that changed
   * since its source run is written as a `dagu.input` label (see
   * `inputLabel`), which the record of the server lacks.
   */
  reused?: readonly InputProvenance[];
  /** The run leaves no trace. The server allows it only with `steps`. */
  ephemeral?: boolean;
  /**
   * The reused steps whose run the editor chose on its own (the cache, or
   * the automatic source), not the user (`automaticReuse`). The server
   * refuses the run unless each comes from a run of the runtime profile
   * state the new run takes, and the run checks that state before any step.
   */
  automaticReuse?: readonly string[];
}

export function buildStartBody(step?: StepRunOptions) {
  return {
    ...stepFields(step),
    labels: runLabels(step),
  };
}

export function buildDraftBody(
  spec: string,
  name: string,
  step?: StepRunOptions
) {
  return {
    spec,
    name,
    ...stepFields(step),
    labels: runLabels(step),
  };
}

// An absent reuse run id, no run of a step and a false ephemeral flag must
// leave no key in the body.
function stepFields(step?: StepRunOptions) {
  if (!step) return {};
  return {
    steps: step.steps,
    ...(step.outputsFromRunId
      ? { outputsFromRunId: step.outputsFromRunId }
      : {}),
    ...(step.outputsFromRuns && Object.keys(step.outputsFromRuns).length > 0
      ? { outputsFromRuns: { ...step.outputsFromRuns } }
      : {}),
    ...(step.ephemeral ? { ephemeral: true } : {}),
    ...(step.automaticReuse && step.automaticReuse.length > 0
      ? { automaticReuse: [...step.automaticReuse] }
      : {}),
  };
}

// The server refuses a label value that does not start with a letter or a
// digit, and a run id can start with '_' or '-'. Such a run gets no
// outputs-from label: the body names it anyway.
const LABEL_VALUE_START = /^[a-zA-Z0-9]/;

function runLabels(step?: StepRunOptions): string[] {
  const from = step?.outputsFromRunId;
  return [
    EDITOR_RUN_LABEL,
    ...(from && LABEL_VALUE_START.test(from)
      ? [`${OUTPUTS_FROM_PREFIX}${from}`]
      : []),
    ...staleLabels(step?.reused ?? []),
  ];
}

// The labels that mark the stale reused steps. One that no label can hold
// (a name or run id too long for a label value) still marks the run: a
// stale input is never dropped silently.
function staleLabels(reused: readonly InputProvenance[]): string[] {
  const stale = reused.filter((r) => r.stale);
  const labels = stale.flatMap((r) => inputLabel(r) ?? []);
  return labels.length < stale.length
    ? [...labels, STALE_UNRECORDED_LABEL]
    : labels;
}
