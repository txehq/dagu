// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import { PersonScopeContext } from '@/features/txe/personScope';
import type { ApiDAGDetails } from '@/features/workflow-workspace/contracts';
import { WorkflowTabsPanel } from '@/features/workflow-workspace/panel/WorkflowTabsPanel';
import { SettingsLeaveGuardProvider } from '@/features/workflow-workspace/settings/useSettingsLeaveGuard';

// The tab bodies are upstream's and tested with their own files; here each
// stands for itself so that only the fork's choice of tabs is under test.
vi.mock('@/features/dags/components/dag-details/DAGWikiTab', () => ({
  default: () => <div data-testid="body-wiki" />,
}));
vi.mock('@/features/dags/components/dag-details/IncidentsTab', () => ({
  default: () => <div data-testid="body-incidents" />,
}));
vi.mock('@/features/dags/components/dag-details/NotificationsTab', () => ({
  default: () => <div data-testid="body-notifications" />,
}));
vi.mock('@/features/workflow-workspace/profile/RuntimeProfileSection', () => ({
  RuntimeProfileSection: () => <div data-testid="body-runtime-profile" />,
}));

const dag = { name: 'nightly' } as ApiDAGDetails;

function renderPanel(url: string, person: boolean) {
  render(
    <PersonScopeContext.Provider value={person}>
      <MemoryRouter initialEntries={[url]}>
        <SettingsLeaveGuardProvider>
          <WorkflowTabsPanel
            overview={<div data-testid="body-overview" />}
            dag={dag}
            fileName="nightly.yaml"
            workspaceName={null}
          />
        </SettingsLeaveGuardProvider>
      </MemoryRouter>
    </PersonScopeContext.Provider>
  );
}

function tabNames(): string[] {
  return screen.getAllByRole('tab').map((tab) => tab.textContent ?? '');
}

describe('Workflow panel in the TXE fork', () => {
  // The fork does not offer the licensed incident feature: no Incidents tab,
  // and a link to it shows the overview.
  it('offers no Incidents tab, and a link to it shows the overview', () => {
    renderPanel('/dags/nightly.yaml?wtab=incidents', false);

    expect(tabNames()).toEqual(['Overview', 'Wiki', 'Notifications']);
    expect(screen.getByTestId('body-overview')).toBeInTheDocument();
    expect(screen.queryByTestId('body-incidents')).not.toBeInTheDocument();
    expect(screen.getByTestId('body-runtime-profile')).toBeInTheDocument();
  });

  // The hub refuses a person a DAG's notification settings and runtime
  // profile settings, so a person is offered neither; a link to the
  // notifications tab shows the overview.
  it('offers a person no Notifications tab and no runtime profile', () => {
    renderPanel('/dags/nightly.yaml?wtab=notifications', true);

    expect(tabNames()).toEqual(['Overview', 'Wiki']);
    expect(screen.getByTestId('body-overview')).toBeInTheDocument();
    expect(screen.queryByTestId('body-notifications')).not.toBeInTheDocument();
    expect(
      screen.queryByTestId('body-runtime-profile')
    ).not.toBeInTheDocument();
  });

  it('keeps the Notifications tab outside a person dashboard', () => {
    renderPanel('/dags/nightly.yaml?wtab=notifications', false);

    expect(screen.getByTestId('body-notifications')).toBeInTheDocument();
  });
});
