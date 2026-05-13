import type { CertificateInspectionResult } from '@sslpin/core';

export const COMPANION_ACTION_PROBE = 'probe';
export type CompanionAction = typeof COMPANION_ACTION_PROBE;
export const COMPANION_USAGE_SENTINEL = 'USAGE';

export interface CompanionRequest {
  id: string;
  action: CompanionAction;
  host: string;
  port?: number;
  servername?: string;
  timeout?: number;
}

export interface CompanionError {
  code: 'BAD_REQUEST' | 'PROBE_FAILED' | 'INTERNAL';
  message: string;
}

export type CompanionResponse =
  | {
      id: string;
      ok: true;
      result: CertificateInspectionResult;
    }
  | {
      id: string;
      ok: false;
      error: CompanionError;
    };

export type CompanionErrorResponse = Extract<CompanionResponse, { ok: false }>;
