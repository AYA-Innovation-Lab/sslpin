import type { LegacyProbeResult, ProbeOptions } from '@sslpin/core';

export function derToPem(der: Buffer): string {
  const base64 = der
    .toString('base64')
    .match(/.{1,64}/g)
    ?.join('\n');
  if (!base64) {
    throw new Error('Invalid DER buffer');
  }

  return `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----\n`;
}

export async function sslPingDomain(
  domain: string,
  options: ProbeOptions = {},
): Promise<LegacyProbeResult> {
  const { inspectTlsHost, toLegacyPins } = await import('@sslpin/core');
  const result = await inspectTlsHost({
    input: domain,
    ...options,
  });

  return toLegacyPins(result);
}
