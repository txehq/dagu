// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import {
  ComponentsParametersTxeEnrolmentClass,
  TxeEnrolRequestClass,
  type components,
  type paths,
} from '@/api/v1/schema';
import type { Client } from 'openapi-fetch';

import { TxeApiError } from './api';

export type Machine = components['schemas']['TxeMachine'];
export type MachineSummary = components['schemas']['TxeMachineSummary'];
export type EnrolmentApplication =
  components['schemas']['TxeEnrolmentApplication'];
export type Enrolment = components['schemas']['TxeEnrolment'];
// The generated client has one enum per place the class appears, with the
// same members; they are mapped by name.
export type EnrolmentClass = `${EnrolmentApplication['class']}`;

// TxeRefusal is a refused enrolment call, with the hub's reason code
// (details.code: unbound, forbidden, not_found, conflict, credential_stale).
export class TxeRefusal extends TxeApiError {
  constructor(
    status: number,
    message: string,
    readonly code: string | undefined
  ) {
    super(status, message);
  }
}

type ErrorBody = { message?: string; details?: { code?: string } } | undefined;

function refusal(response: Response, error: unknown): TxeRefusal {
  const body = error as ErrorBody;
  return new TxeRefusal(
    response.status,
    body?.message ?? `Request failed (${response.status})`,
    body?.details?.code
  );
}

// The machine enrolment routes the dashboard uses. A machine applies from
// its own worker or reviewer client (the CLI, not here); a person of the
// machine's owner approves one application and may revoke an enrolment.
// The hub decides who may do each; this module only calls it.
export interface TxeEnrolmentApi {
  // listMachines returns the machines the hub lets the caller see. Only for
  // a person of the machine's owner does it count pending applications.
  listMachines(): Promise<MachineSummary[]>;
  getMachine(machineId: string): Promise<Machine>;
  listApplications(machineId: string): Promise<EnrolmentApplication[]>;
  // enrol approves the application with exactly the identity that was read
  // on it, so a different application on file is refused, not approved.
  enrol(application: EnrolmentApplication): Promise<Enrolment>;
  listEnrolments(machineId: string): Promise<Enrolment[]>;
  revokeEnrolment(
    machineId: string,
    enrolmentClass: EnrolmentClass,
    reason: string
  ): Promise<Enrolment>;
}

export function createTxeEnrolmentApi(client: Client<paths>): TxeEnrolmentApi {
  return {
    async listMachines() {
      const res = await client.GET('/txe/machines');
      if (!res.data) throw refusal(res.response, res.error);
      return res.data.machines;
    },
    async getMachine(machineId) {
      const res = await client.GET('/txe/machines/{machineId}', {
        params: { path: { machineId } },
      });
      if (!res.data) throw refusal(res.response, res.error);
      return res.data;
    },
    async listApplications(machineId) {
      const res = await client.GET(
        '/txe/machines/{machineId}/enrolment-applications',
        { params: { path: { machineId } } }
      );
      if (!res.data) throw refusal(res.response, res.error);
      return res.data.applications;
    },
    async enrol(application) {
      const res = await client.POST('/txe/machines/{machineId}/enrolments', {
        params: { path: { machineId: application.machine_id } },
        body: {
          class: TxeEnrolRequestClass[application.class],
          client_id: application.client_id,
          issuer: application.issuer,
          subject: application.subject,
        },
      });
      if (!res.data) throw refusal(res.response, res.error);
      return res.data;
    },
    async listEnrolments(machineId) {
      const res = await client.GET('/txe/machines/{machineId}/enrolments', {
        params: { path: { machineId } },
      });
      if (!res.data) throw refusal(res.response, res.error);
      return res.data.enrolments;
    },
    async revokeEnrolment(machineId, enrolmentClass, reason) {
      const res = await client.POST(
        '/txe/machines/{machineId}/enrolments/{class}/revoke',
        {
          params: {
            path: {
              machineId,
              class: ComponentsParametersTxeEnrolmentClass[enrolmentClass],
            },
          },
          body: { reason },
        }
      );
      if (!res.data) throw refusal(res.response, res.error);
      return res.data;
    },
  };
}
