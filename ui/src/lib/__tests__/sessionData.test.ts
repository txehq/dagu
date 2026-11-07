// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { outputCache } from '@/features/visual-editor/run/outputCache';
import { draftStorageKey } from '@/features/visual-editor/run/draftStorage';
import {
  clearSessionData,
  registerSessionDataReset,
  SESSION_DATA_PREFIXES,
} from '../sessionData';

describe('clearSessionData', () => {
  it('removes every session-data key and keeps preferences', () => {
    localStorage.clear();
    localStorage.setItem('dagu.output-cache.v1:local:a.yaml', '{}');
    localStorage.setItem(draftStorageKey('local', 'a.yaml'), '{}');
    localStorage.setItem('dagu_wiki_tabs:ops', '{}');
    localStorage.setItem('dagu_doc_tabs', '{}');
    localStorage.setItem('dagu_dag_tabs', '[]');
    localStorage.setItem('sidebarExpanded', 'true');
    localStorage.setItem('dagu_auth_token', 'kept by the auth session');

    clearSessionData();

    const left = Object.keys(localStorage).sort();
    expect(left).toEqual(['dagu_auth_token', 'sidebarExpanded']);
  });

  it('resets the in-memory copies, the output cache among them', () => {
    const reset = vi.fn();
    const unregister = registerSessionDataReset(reset);
    const scope = { remoteNode: 'local', fileName: 'a.yaml' };
    outputCache.put(scope, 'build', {
      runId: 'r1',
      capturedAt: 1,
      stepHash: 'h',
      values: { OUT: 'secret of account A' },
    });

    expect(Object.keys(outputCache.entries(scope))).toEqual(['build']);
    expect(
      Object.keys(localStorage).some((k) => k.startsWith('dagu.output-cache'))
    ).toBe(true);

    clearSessionData();

    expect(reset).toHaveBeenCalledTimes(1);
    expect(outputCache.entries(scope)).toEqual({});
    unregister();
  });
});

// Every file that uses localStorage is classified. Session data must be
// stored under SESSION_DATA_PREFIXES, which clearSessionData removes when a
// session ends; a preference or the auth session is what may stay. A new
// file that uses localStorage fails here until it is classified, so a new
// store of an account's data cannot outlive the account's session unnoticed
// (TXE-5923).
const SESSION_DATA = new Set([
  'contexts/TabContext.tsx',
  'contexts/WikiPageTabContext.tsx',
  'features/visual-editor/run/draftStorage.ts',
  'features/visual-editor/run/outputCache.ts',
  'lib/sessionData.ts',
]);
const AUTH = new Set([
  'features/dags/components/dag-details/notifications/notificationDrafts.ts',
  'features/dags/components/dag-details/WebhookTab.tsx',
  'features/txe/personSignal.ts',
  'index.tsx',
  'lib/authSession.ts',
  'pages/api-docs/index.tsx',
  'pages/api-keys/APIKeyFormModal.tsx',
  'pages/api-keys/index.tsx',
  'pages/audit-logs/index.tsx',
  'pages/remote-nodes/index.tsx',
  'pages/terminal/index.tsx',
  'pages/users/index.tsx',
  'pages/users/ResetPasswordModal.tsx',
  'pages/users/UserFormModal.tsx',
  'pages/webhooks/index.tsx',
]);
const PREFERENCE = new Set([
  'App.tsx',
  'components/LicenseBanner.tsx',
  'components/SplitLayout.tsx',
  'components/UpdateBanner.tsx',
  'components/WorkspaceDeprecationNotice.tsx',
  'contexts/UserPreference.tsx',
  'features/cockpit/components/MobileKanbanBoard.tsx',
  'features/dags/components/common/SubRunStackModal.tsx',
  'features/dags/components/dag-editor/DAGEditorWithDocs.tsx',
  'features/dags/components/dag-list/DAGTable.tsx',
  'features/dags/components/step-details/StepSideDrawer.tsx',
  'features/dags/components/visualization/GraphResizeHandle.tsx',
  'features/peek/OverlayResizeHandle.tsx',
  'features/visual-editor/canvas/useCanvasDetails.ts',
  'features/visual-editor/canvas/useCanvasDirection.ts',
  'features/visual-editor/recentActions.ts',
  'features/workflow-workspace/canvas/useRightColumn.ts',
  'features/workflow-workspace/canvas/useYamlPanelMemory.ts',
  'features/workflow-workspace/data/useVisibleRuns.ts',
  'features/workflow-workspace/dock/DockContext.tsx',
  'hooks/useStoredValue.ts',
  'layouts/Layout.tsx',
  'lib/local-storage-migration.ts',
  'lib/workspace.ts',
  'pages/overview/index.tsx',
  'pages/wiki/components/WikiPageOutlinePanel.tsx',
]);

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      return name === '__tests__' ? [] : sourceFiles(path);
    }
    return /\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name)
      ? [path]
      : [];
  });
}

describe('localStorage classification', () => {
  it('classifies every file that uses localStorage', () => {
    const src = join(__dirname, '..', '..');
    const users = sourceFiles(src)
      .filter((path) => readFileSync(path, 'utf8').includes('localStorage'))
      .map((path) => relative(src, path).split('\\').join('/'));
    const unclassified = users.filter(
      (file) =>
        !SESSION_DATA.has(file) && !AUTH.has(file) && !PREFERENCE.has(file)
    );
    expect(unclassified).toEqual([]);
  });

  it('stores session data only under the prefixes it clears', () => {
    expect(SESSION_DATA_PREFIXES).toEqual(
      expect.arrayContaining([
        'dagu.output-cache.v1:',
        'dagu:draft:',
        'dagu_wiki_tabs',
        'dagu_doc_tabs',
        'dagu_dag_tabs',
      ])
    );
  });
});
