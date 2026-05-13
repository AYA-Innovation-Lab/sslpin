import crypto from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
import {
  DEFAULT_EXPIRING_SOON_DAYS,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_TLS_PORT,
  MAX_PORT_NUMBER,
  PEM_WRAP_WIDTH,
  UNKNOWN_VALUE,
} from './constants.js';
import { buildWarnings, ensurePositiveInteger } from './shared.js';
import type {
  CertificateInspectionResult,
  CertificatePinEntry,
  InspectTlsHostOptions,
  ProbeOptions,
} from './types.js';

export interface RawCertificateInput {
  raw: Buffer;
  index: number;
  isLeaf: boolean;
  subject?: Record<string, unknown> | string;
  issuer?: Record<string, unknown> | string;
  validFrom?: string;
  validTo?: string;
  serialNumber?: string;
}

interface PeerCertificateEx extends tls.PeerCertificate {
  issuerCertificate?: PeerCertificateEx;
}

interface Target {
  input: string;
  host: string;
  port: number;
  servername: string;
}

interface ConnectionSnapshot {
  ip: string;
  protocol: string;
  cipher: string;
  authorized: boolean;
  authorizationError?: string;
  peerChain: PeerCertificateEx;
}

export function derToPem(der: Buffer): string {
  const base64 = der
    .toString('base64')
    .match(new RegExp(`.{1,${PEM_WRAP_WIDTH}}`, 'g'))
    ?.join('\n');

  if (!base64) {
    throw new Error('Invalid DER buffer');
  }

  return `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----\n`;
}

function normalizeTarget(
  input: string,
  options: Partial<Pick<Target, 'port' | 'servername'>> = {},
): Target {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error('Target is required');
  }

  let parsed: URL;
  if (/^[a-zA-Z]+:\/\//.test(trimmed)) {
    parsed = new URL(trimmed);
    if (parsed.protocol !== 'https:') {
      throw new Error('Only HTTPS URLs are supported');
    }
  } else {
    parsed = new URL(`https://${trimmed}`);
  }

  const host = parsed.hostname;
  if (!host) {
    throw new Error(`Unable to parse host from target: ${input}`);
  }

  const defaultPort = parsed.port ? Number(parsed.port) : DEFAULT_TLS_PORT;
  const port = options.port ?? defaultPort;
  ensurePositiveInteger(port, 'port');
  if (port > MAX_PORT_NUMBER) {
    throw new Error(`port must be less than or equal to ${MAX_PORT_NUMBER}`);
  }

  const servername = options.servername ?? host;
  if (!servername) {
    throw new Error('servername cannot be empty');
  }

  return {
    input,
    host,
    port,
    servername,
  };
}

function formatName(name?: Record<string, unknown> | string): string {
  if (!name) {
    return UNKNOWN_VALUE;
  }

  if (typeof name === 'string') {
    return name;
  }

  const priority = ['CN', 'O', 'OU', 'L', 'ST', 'C'];
  const used = new Set<string>();
  const orderedEntries: Array<[string, string]> = [];

  for (const key of priority) {
    const value = name[key];
    if (typeof value === 'string' && value) {
      orderedEntries.push([key, value]);
      used.add(key);
    }
  }

  for (const [key, value] of Object.entries(name)) {
    if (!used.has(key) && typeof value === 'string' && value) {
      orderedEntries.push([key, value]);
    }
  }

  if (orderedEntries.length === 0) {
    return UNKNOWN_VALUE;
  }

  return orderedEntries.map(([key, value]) => `${key}=${value}`).join(', ');
}

function getPublicKeyDescription(keyObject: crypto.KeyObject): string {
  const keyType = keyObject.asymmetricKeyType?.toUpperCase() ?? UNKNOWN_VALUE.toUpperCase();
  const keyDetails = keyObject.asymmetricKeyDetails;

  if (keyType === 'RSA' && keyDetails?.modulusLength) {
    return `${keyType} ${keyDetails.modulusLength}`;
  }

  if (keyType === 'EC' && keyDetails?.namedCurve) {
    return `${keyType} ${keyDetails.namedCurve}`;
  }

  return keyType;
}

export function computeCertificatePins(input: RawCertificateInput): CertificatePinEntry {
  if (!input.raw) {
    throw new Error('Certificate does not contain raw DER data');
  }

  const pem = derToPem(input.raw);
  const x509 = new crypto.X509Certificate(pem);
  const spkiDer = x509.publicKey.export({ type: 'spki', format: 'der' });

  return {
    index: input.index,
    isLeaf: input.isLeaf,
    subject: formatName(input.subject),
    issuer: formatName(input.issuer),
    validFrom: input.validFrom ?? x509.validFrom,
    validTo: input.validTo ?? x509.validTo,
    serialNumber: input.serialNumber ?? x509.serialNumber,
    sha1Fingerprint: crypto.createHash('sha1').update(input.raw).digest('hex').toUpperCase(),
    sha256Fingerprint: crypto.createHash('sha256').update(input.raw).digest('hex').toUpperCase(),
    spkiSha256: crypto.createHash('sha256').update(spkiDer).digest('base64'),
    spkiSha256Hex: crypto.createHash('sha256').update(spkiDer).digest('hex').toUpperCase(),
    signatureAlgorithm: x509.signatureAlgorithm ?? UNKNOWN_VALUE,
    publicKey: getPublicKeyDescription(x509.publicKey),
    pem,
  };
}

export const createCertificateRecordFromRaw = computeCertificatePins;

function extractCertificateChain(chain: PeerCertificateEx): PeerCertificateEx[] {
  const certificates: PeerCertificateEx[] = [];
  const visited = new Set<PeerCertificateEx>();
  let current: PeerCertificateEx | undefined = chain;

  while (current && !visited.has(current)) {
    visited.add(current);
    if (!current.raw) {
      break;
    }

    certificates.push(current);

    if (!current.issuerCertificate || current.issuerCertificate === current) {
      break;
    }

    current = current.issuerCertificate;
  }

  return certificates;
}

export function applyLeafOnlyFilter(
  certificates: CertificatePinEntry[],
  leafOnly: boolean | undefined,
): CertificatePinEntry[] {
  if (!leafOnly) {
    return certificates;
  }

  return certificates.filter((record) => record.isLeaf);
}

function toCertificatePinEntry(
  certificate: PeerCertificateEx,
  index: number,
  isLeaf: boolean,
): CertificatePinEntry {
  return computeCertificatePins({
    raw: certificate.raw,
    index,
    isLeaf,
    subject: certificate.subject as unknown as Record<string, unknown>,
    issuer: certificate.issuer as unknown as Record<string, unknown>,
    validFrom: certificate.valid_from,
    validTo: certificate.valid_to,
    serialNumber: certificate.serialNumber,
  });
}

export function detectHostnameMismatchFromPem(pem: string, servername: string): boolean {
  try {
    const leafX509 = new crypto.X509Certificate(pem);
    const isIpAddress = net.isIP(servername) > 0;
    const match = isIpAddress
      ? leafX509.checkIP(servername)
      : leafX509.checkHost(servername, { subject: 'default' });

    return !match;
  } catch {
    return false;
  }
}

function getHostnameMismatchFlag(certificates: CertificatePinEntry[], servername: string): boolean {
  const leaf = certificates.find((cert) => cert.isLeaf) ?? certificates[0];
  if (!leaf?.pem) {
    return false;
  }

  return detectHostnameMismatchFromPem(leaf.pem, servername);
}

function connectTls(target: Target, timeoutMs: number): Promise<ConnectionSnapshot> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: target.host,
      port: target.port,
      servername: target.servername,
      rejectUnauthorized: false,
    });

    let settled = false;
    const fail = (error: Error): void => {
      if (settled) {
        return;
      }

      settled = true;
      socket.removeAllListeners();
      socket.destroy();
      reject(error);
    };

    socket.once('error', fail);
    socket.setTimeout(timeoutMs, () => {
      fail(new Error(`Connection timed out after ${timeoutMs}ms`));
    });

    socket.once('secureConnect', () => {
      const chain = socket.getPeerCertificate(true) as PeerCertificateEx;
      if (!chain?.raw) {
        fail(new Error('No certificate chain available'));
        return;
      }

      settled = true;
      socket.removeAllListeners();
      socket.setTimeout(0);
      socket.end();

      resolve({
        ip: socket.remoteAddress ?? target.host,
        protocol: socket.getProtocol() ?? 'TLS',
        cipher: socket.getCipher()?.name ?? UNKNOWN_VALUE,
        authorized: socket.authorized,
        authorizationError:
          typeof socket.authorizationError === 'string'
            ? socket.authorizationError
            : socket.authorizationError?.message,
        peerChain: chain,
      });
    });
  });
}

export async function inspectTlsHost(
  options: InspectTlsHostOptions,
): Promise<CertificateInspectionResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  ensurePositiveInteger(timeoutMs, 'timeoutMs');

  const expiringSoonDays = options.expiringSoonDays ?? DEFAULT_EXPIRING_SOON_DAYS;
  ensurePositiveInteger(expiringSoonDays, 'expiringSoonDays');

  const target = normalizeTarget(options.input, options);
  const startedAt = Date.now();
  const connectionSnapshot = await connectTls(target, timeoutMs);

  const fullChain = extractCertificateChain(connectionSnapshot.peerChain).map(
    (certificate, index) => toCertificatePinEntry(certificate, index + 1, index === 0),
  );

  const certificates = applyLeafOnlyFilter(fullChain, options.leafOnly);
  const hostnameMismatch = getHostnameMismatchFlag(fullChain, target.servername);
  const warnings = buildWarnings(
    {
      certificates,
      target: {
        servername: target.servername,
      },
    },
    {
      expiringSoonDays,
      hostnameMismatch,
    },
  );

  return {
    target,
    connection: {
      ip: connectionSnapshot.ip,
      protocol: connectionSnapshot.protocol,
      cipher: connectionSnapshot.cipher,
      timeMs: Date.now() - startedAt,
      authorized: connectionSnapshot.authorized,
      authorizationError: connectionSnapshot.authorizationError,
    },
    certificates,
    warnings,
  };
}

export async function probeTls(
  input: string,
  options: ProbeOptions = {},
): Promise<CertificateInspectionResult> {
  return inspectTlsHost({
    input,
    ...options,
  });
}
