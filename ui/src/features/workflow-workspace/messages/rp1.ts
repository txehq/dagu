// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

import { defineMessages } from './define';

// Reuse of outputs across runtime profile states (TXE-6145): the cache and
// the automatic choice take only runs of the state the step run takes; a run
// the user chooses may be of another, with a warning.
export default defineMessages({
  en: {
    'cached under another runtime profile':
      'cached under another runtime profile',
    'Run {id} ran under another runtime profile, or one that is not known. The step runs with the profile it takes now.':
      'Run {id} ran under another runtime profile, or one that is not known. The step runs with the profile it takes now.',
  },
  'zh-CN': {
    'cached under another runtime profile': '缓存于其他运行时配置下',
    'Run {id} ran under another runtime profile, or one that is not known. The step runs with the profile it takes now.':
      '运行 {id} 使用了其他运行时配置，或其配置未知。此步骤将使用当前的配置运行。',
  },
  ja: {
    'cached under another runtime profile':
      '別のランタイムプロファイルでキャッシュ済み',
    'Run {id} ran under another runtime profile, or one that is not known. The step runs with the profile it takes now.':
      '実行 {id} は別のランタイムプロファイル、または不明なプロファイルで実行されました。このステップは現在のプロファイルで実行されます。',
  },
});
