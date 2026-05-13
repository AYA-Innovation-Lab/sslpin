import { inspectTlsHost } from '@sslpin/core/node';
import { COMPANION_ACTION_PROBE, type CompanionRequest, type CompanionResponse } from './types.js';

export type CompanionProbeExecutor = (
  request: CompanionRequest,
) => Promise<Extract<CompanionResponse, { ok: true }>['result']>;

function createError(
  id: string,
  code: Extract<CompanionResponse, { ok: false }>['error']['code'],
  message: string,
): Extract<CompanionResponse, { ok: false }> {
  return {
    id,
    ok: false,
    error: {
      code,
      message,
    },
  };
}

function validatePositiveInteger(value: number | undefined, field: string): string | null {
  if (value === undefined) {
    return null;
  }

  if (!Number.isInteger(value) || Number(value) <= 0) {
    return `${field} must be a positive integer`;
  }

  return null;
}

function validateRequest(
  rawRequest: unknown,
): CompanionRequest | Extract<CompanionResponse, { ok: false }> {
  const request = rawRequest as Partial<CompanionRequest> | undefined;
  const id = typeof request?.id === 'string' ? request.id : 'unknown';

  if (!request || typeof request !== 'object') {
    return createError(id, 'BAD_REQUEST', 'Request must be a JSON object');
  }

  if (typeof request.id !== 'string' || request.id.trim() === '') {
    return createError(id, 'BAD_REQUEST', 'id is required and must be a non-empty string');
  }

  if (request.action !== COMPANION_ACTION_PROBE) {
    return createError(request.id, 'BAD_REQUEST', `action must be "${COMPANION_ACTION_PROBE}"`);
  }

  if (typeof request.host !== 'string' || request.host.trim() === '') {
    return createError(
      request.id,
      'BAD_REQUEST',
      'host is required and must be a non-empty string',
    );
  }

  const portError = validatePositiveInteger(request.port, 'port');
  if (portError) {
    return createError(request.id, 'BAD_REQUEST', portError);
  }

  if (request.port !== undefined && request.port > 65_535) {
    return createError(request.id, 'BAD_REQUEST', 'port must be less than or equal to 65535');
  }

  const timeoutError = validatePositiveInteger(request.timeout, 'timeout');
  if (timeoutError) {
    return createError(request.id, 'BAD_REQUEST', timeoutError);
  }

  if (request.servername !== undefined && request.servername.trim() === '') {
    return createError(request.id, 'BAD_REQUEST', 'servername cannot be empty when provided');
  }

  return {
    id: request.id,
    action: COMPANION_ACTION_PROBE,
    host: request.host.trim(),
    port: request.port,
    servername: request.servername?.trim(),
    timeout: request.timeout,
  };
}

function isErrorResponse(
  value: CompanionRequest | Extract<CompanionResponse, { ok: false }>,
): value is Extract<CompanionResponse, { ok: false }> {
  return 'ok' in value && value.ok === false;
}

export async function handleCompanionRequest(
  rawRequest: unknown,
  probeExecutor: CompanionProbeExecutor = async (request) =>
    inspectTlsHost({
      input: request.host,
      port: request.port,
      servername: request.servername,
      timeoutMs: request.timeout,
    }),
): Promise<CompanionResponse> {
  const validated = validateRequest(rawRequest);
  if (isErrorResponse(validated)) {
    return validated;
  }

  try {
    const result = await probeExecutor(validated);
    return {
      id: validated.id,
      ok: true,
      result,
    };
  } catch (error) {
    return createError(
      validated.id,
      'PROBE_FAILED',
      error instanceof Error ? error.message : String(error),
    );
  }
}
