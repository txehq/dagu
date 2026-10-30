// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Stream } from '@/api/v1/schema';
import { useQuery } from '@/hooks/api';
import { InlineLogViewer } from '../InlineLogViewer';

vi.mock('@/hooks/api', () => ({
  useQuery: vi.fn(),
}));

vi.mock('@/contexts/RemoteNodeContext', () => ({
  useRemoteNode: () => 'local',
}));

const stepLogPath = '/dag-runs/{name}/{dagRunId}/steps/{stepName}/log';

type QueryCall = {
  path: string;
  init: unknown;
  options: { refreshInterval?: number };
};

const mockedUseQuery = vi.mocked(
  useQuery as unknown as (
    path: string,
    init: unknown,
    options: QueryCall['options']
  ) => unknown
);

describe('InlineLogViewer', () => {
  let calls: QueryCall[];
  let mutate: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    calls = [];
    mutate = vi.fn();
    mockedUseQuery.mockImplementation((path, init, options) => {
      calls.push({ path, init, options });
      return {
        data: init
          ? { content: 'claim held\n', totalLines: 1, lineCount: 1 }
          : undefined,
        isLoading: false,
        mutate,
      };
    });
  });

  const logOptions = () =>
    calls.filter((c) => c.path === stepLogPath && c.init).map((c) => c.options);
  const lastLogOptions = () => {
    const options = logOptions();
    return options[options.length - 1];
  };

  const viewer = (live: boolean) => (
    <InlineLogViewer
      dagName="txe-decide-01M9R1G0000000000000000000"
      dagRunId="txe-rigfailed0000000000000000001"
      stepName="execute"
      stream={Stream.stderr}
      live={live}
    />
  );

  it('fetches a finished step log once and does not poll it', () => {
    render(viewer(false));

    expect(screen.getByText('claim held')).toBeInTheDocument();
    const options = logOptions();
    expect(options.length).toBeGreaterThan(0);
    for (const o of options) {
      expect(o.refreshInterval).toBe(0);
    }
    expect(mutate).not.toHaveBeenCalled();
  });

  it('polls a running step log, and fetches once more when the step stops', () => {
    const { rerender } = render(viewer(true));
    expect(lastLogOptions()?.refreshInterval).toBe(2000);
    expect(mutate).not.toHaveBeenCalled();

    rerender(viewer(false));
    expect(lastLogOptions()?.refreshInterval).toBe(0);
    expect(mutate).toHaveBeenCalledTimes(1);

    // Staying stopped asks for nothing more.
    rerender(viewer(false));
    expect(mutate).toHaveBeenCalledTimes(1);

    // A retried step is live again and is polled again.
    rerender(viewer(true));
    expect(lastLogOptions()?.refreshInterval).toBe(2000);
  });
});
