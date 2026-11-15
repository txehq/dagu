// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

import { APIKeyLimitSource, type components } from '@/api/v1/schema';

type APIKeysListResponse = components['schemas']['APIKeysListResponse'];

export type APIKeyLimit = { limit: number; source: APIKeyLimitSource };

// A server that predates unlicensedApiKeyLimit enforces the community default.
export const OLDER_SERVER_API_KEY_LIMIT: APIKeyLimit = {
  limit: 2,
  source: APIKeyLimitSource.community_default,
};

/**
 * Reads the key limit the server enforces while it has no active paid license.
 * Zero means no limit.
 */
export function readAPIKeyLimit(
  data: Partial<APIKeysListResponse> | null | undefined
): APIKeyLimit {
  const limit = data?.unlicensedApiKeyLimit;
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 0) {
    return OLDER_SERVER_API_KEY_LIMIT;
  }
  return {
    limit,
    source:
      data?.unlicensedApiKeyLimitSource === APIKeyLimitSource.fork_policy
        ? APIKeyLimitSource.fork_policy
        : APIKeyLimitSource.community_default,
  };
}
