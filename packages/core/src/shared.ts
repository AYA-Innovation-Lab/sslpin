import {
  DEFAULT_EXPIRING_SOON_DAYS,
  LEGACY_DATA_SIZE_BYTES,
  MILLISECONDS_PER_DAY,
  UNKNOWN_VALUE,
} from './constants.js';
import type {
  BuildWarningsOptions,
  CertificateInspectionResult,
  CertificatePinEntry,
  CopyKind,
  InspectionWarning,
  LegacyProbeResult,
  SerializableInspectionResult,
  WarningBuildInput,
} from './types.js';

export function ensurePositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
}

export function parseDateSafe(input: string): Date | null {
  const timestamp = Date.parse(input);
  if (Number.isNaN(timestamp)) {
    return null;
  }
  return new Date(timestamp);
}

function hasMissingData(cert: CertificatePinEntry): string[] {
  const missing: string[] = [];

  if (!cert.subject || cert.subject === UNKNOWN_VALUE) {
    missing.push('subject');
  }
  if (!cert.issuer || cert.issuer === UNKNOWN_VALUE) {
    missing.push('issuer');
  }
  if (!cert.validTo || !parseDateSafe(cert.validTo)) {
    missing.push('validTo');
  }
  if (!cert.serialNumber) {
    missing.push('serialNumber');
  }
  if (!cert.sha256Fingerprint) {
    missing.push('sha256Fingerprint');
  }
  if (!cert.spkiSha256) {
    missing.push('spkiSha256');
  }
  if (!cert.pem) {
    missing.push('pem');
  }

  return missing;
}

function evaluateValidityWarnings(
  certificates: CertificatePinEntry[],
  expiringSoonDays = DEFAULT_EXPIRING_SOON_DAYS,
): InspectionWarning[] {
  const now = Date.now();
  const expiringThreshold = now + expiringSoonDays * MILLISECONDS_PER_DAY;
  const warnings: InspectionWarning[] = [];

  for (const cert of certificates) {
    const validTo = parseDateSafe(cert.validTo);
    if (!validTo) {
      continue;
    }

    const validToMs = validTo.getTime();
    if (validToMs < now) {
      warnings.push({
        code: 'CERT_EXPIRED',
        message: `Certificate ${cert.index} expired on ${validTo.toISOString()}`,
        certIndex: cert.index,
        severity: 'warning',
      });
      continue;
    }

    if (validToMs <= expiringThreshold) {
      warnings.push({
        code: 'CERT_EXPIRING_SOON',
        message: `Certificate ${cert.index} expires on ${validTo.toISOString()}`,
        certIndex: cert.index,
        severity: 'warning',
      });
    }
  }

  return warnings;
}

function evaluateMissingDataWarnings(certificates: CertificatePinEntry[]): InspectionWarning[] {
  if (certificates.length === 0) {
    return [
      {
        code: 'MISSING_CERTIFICATE_DATA',
        message: 'No certificate data was returned by the remote host.',
        certIndex: 0,
        severity: 'warning',
      },
    ];
  }

  const warnings: InspectionWarning[] = [];
  for (const cert of certificates) {
    const missing = hasMissingData(cert);
    if (missing.length > 0) {
      warnings.push({
        code: 'MISSING_CERTIFICATE_DATA',
        message: `Certificate ${cert.index} is missing fields: ${missing.join(', ')}`,
        certIndex: cert.index,
        severity: 'warning',
      });
    }
  }

  return warnings;
}

export function buildHostnameMismatchWarning(message: string): InspectionWarning {
  return {
    code: 'HOSTNAME_MISMATCH',
    message,
    certIndex: 1,
    severity: 'warning',
  };
}

export function buildWarnings(
  result: WarningBuildInput,
  options: BuildWarningsOptions = {},
): InspectionWarning[] {
  const expiringSoonDays = options.expiringSoonDays ?? DEFAULT_EXPIRING_SOON_DAYS;
  ensurePositiveInteger(expiringSoonDays, 'expiringSoonDays');

  const warnings = [
    ...evaluateMissingDataWarnings(result.certificates),
    ...evaluateValidityWarnings(result.certificates, expiringSoonDays),
  ];

  if (options.hostnameMismatch) {
    const servername = result.target?.servername;
    const suffix = servername ? ` for ${servername}` : '';
    warnings.push(
      buildHostnameMismatchWarning(`Hostname mismatch: certificate is not valid${suffix}`),
    );
  }

  return warnings;
}

export function getLeafCertificate(result: CertificateInspectionResult): CertificatePinEntry {
  const leaf = result.certificates.find((cert) => cert.isLeaf) ?? result.certificates[0];

  if (!leaf) {
    throw new Error('No certificate data available');
  }

  return leaf;
}

export function getCopyValue(result: CertificateInspectionResult, kind: CopyKind): string {
  const leaf = getLeafCertificate(result);

  switch (kind) {
    case 'spki':
      return leaf.spkiSha256;
    case 'sha256':
      return leaf.sha256Fingerprint;
    case 'pem':
      return leaf.pem;
    default: {
      const exhaustive: never = kind;
      throw new Error(`Unsupported copy kind: ${String(exhaustive)}`);
    }
  }
}

export function toSerializableResult(
  result: CertificateInspectionResult,
): SerializableInspectionResult {
  return {
    host: result.target.host,
    ip: result.connection.ip,
    port: result.target.port,
    tlsVersion: result.connection.protocol,
    cipher: result.connection.cipher,
    durationMs: result.connection.timeMs,
    warnings: result.warnings,
    certificates: result.certificates,
  };
}

export function toLegacyPins(result: CertificateInspectionResult): LegacyProbeResult {
  return {
    pins: result.certificates.map((cert) => ({
      index: cert.index,
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      serialNumber: cert.serialNumber,
      sha1Fingerprint: cert.sha1Fingerprint,
      sha256Fingerprint: cert.sha256Fingerprint,
      spkiSha256: cert.spkiSha256,
      spkiSha256Hex: cert.spkiSha256Hex,
      signatureAlgorithm: cert.signatureAlgorithm,
      publicKey: cert.publicKey,
      certificate: cert.pem,
    })),
    ip: result.connection.ip,
    port: result.target.port,
    tlsVersion: result.connection.protocol,
    cipher: result.connection.cipher,
    time: result.connection.timeMs,
    status: 'OK',
    dataSize: LEGACY_DATA_SIZE_BYTES,
  };
}
