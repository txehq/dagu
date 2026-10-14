// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { components, paths } from '@/api/v1/schema';
import type { Client } from 'openapi-fetch';

import { TxeApiError } from './api';

export type BindingRequest = components['schemas']['TxeBindingRequest'];
export type Binding = components['schemas']['TxeBinding'];
export type Owner = components['schemas']['TxeOwner'];

// The access routes the dashboard uses: a person asks to be bound, and the
// platform administrator binds, creates owners and revokes. The hub decides
// who may do each; this module only calls it.
export interface TxeAccessApi {
  requestAccess(): Promise<void>;
  listRequests(): Promise<BindingRequest[]>;
  listOwners(): Promise<Owner[]>;
  createOwner(displayName: string): Promise<Owner>;
  approve(ownerId: string, request: BindingRequest): Promise<Binding>;
  listBindings(ownerId: string): Promise<Binding[]>;
  revoke(ownerId: string, bindingId: string, reason: string): Promise<void>;
}

type ErrorBody = { message?: string; details?: { code?: string } } | undefined;

function failure(response: Response, error: unknown): TxeApiError {
  const body = error as ErrorBody;
  return new TxeApiError(
    response.status,
    body?.message ??
      body?.details?.code ??
      `Request failed (${response.status})`
  );
}

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

// ulid returns a ULID: 48 bits of milliseconds then 80 random bits, in
// Crockford base32. Owner ids are minted by the caller (own_<ULID>).
export function ulid(now: number = Date.now()): string {
  let time = '';
  let ms = now;
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD[ms % 32] + time;
    ms = Math.floor(ms / 32);
  }
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  let bits = 0;
  let value = 0;
  let random = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      random += CROCKFORD[(value >> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  return time + random;
}

export function createTxeAccessApi(client: Client<paths>): TxeAccessApi {
  return {
    async requestAccess() {
      const res = await client.POST('/txe/binding-requests');
      if (!res.data) throw failure(res.response, res.error);
    },
    async listRequests() {
      const res = await client.GET('/txe/binding-requests');
      if (!res.data) throw failure(res.response, res.error);
      return res.data.requests;
    },
    async listOwners() {
      const res = await client.GET('/txe/installation');
      if (!res.data) throw failure(res.response, res.error);
      return res.data.owners;
    },
    async createOwner(displayName) {
      const res = await client.POST('/txe/owners', {
        body: { owner_id: `own_${ulid()}`, display_name: displayName },
      });
      if (!res.data) throw failure(res.response, res.error);
      return res.data;
    },
    async approve(ownerId, request) {
      const res = await client.POST('/txe/owners/{ownerId}/bindings', {
        params: { path: { ownerId } },
        body: {
          issuer: request.issuer,
          subject: request.subject,
          request_generation: request.generation,
        },
      });
      if (!res.data) throw failure(res.response, res.error);
      return res.data;
    },
    async listBindings(ownerId) {
      const res = await client.GET('/txe/owners/{ownerId}/bindings', {
        params: { path: { ownerId } },
      });
      if (!res.data) throw failure(res.response, res.error);
      return res.data.bindings;
    },
    async revoke(ownerId, bindingId, reason) {
      const res = await client.POST(
        '/txe/owners/{ownerId}/bindings/{bindingId}/revoke',
        { params: { path: { ownerId, bindingId } }, body: { reason } }
      );
      if (res.error) throw failure(res.response, res.error);
    },
  };
}
