import {
  DEFAULT_EXPIRING_SOON_DAYS,
  PEM_WRAP_WIDTH,
  SERIALIZATION_SCHEMA_VERSION,
  UNKNOWN_VALUE,
} from './constants.js';
import { buildWarnings, getCopyValue, toLegacyPins } from './shared.js';
import type {
  CertificatePinEntry,
  ChromiumCertificateChainInput,
  FirefoxSecurityInput,
  ProbeResult,
} from './types.js';

const NAME_OID_LABELS: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '1.2.840.113549.1.9.1': 'emailAddress',
};

const SIGNATURE_ALGORITHM_OIDS: Record<string, string> = {
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.3.101.112': 'Ed25519',
};

const PUBLIC_KEY_ALGORITHM_OIDS: Record<string, string> = {
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.10045.2.1': 'EC',
  '1.3.101.112': 'Ed25519',
};

interface DerElement {
  tag: number;
  start: number;
  end: number;
  valueStart: number;
  valueEnd: number;
}

interface ParsedCertificateMeta {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  signatureAlgorithm: string;
  publicKey: string;
  spkiDer: ArrayBuffer;
}

interface FirefoxCertificateLike {
  subject?: string;
  issuer?: string;
  validity?: {
    start?: number;
    end?: number;
  };
  serialNumber?: string;
  fingerprint?: {
    sha1?: string;
    sha256?: string;
  };
  subjectPublicKeyInfoDigest?: {
    sha256?: string;
  };
  rawDER?: ArrayBuffer;
}

interface FirefoxSecurityInfoLike {
  certificates?: FirefoxCertificateLike[];
  isDomainMismatch?: boolean;
  state?: string;
  protocolVersion?: string;
  cipherSuite?: string;
  isUntrusted?: boolean;
  errorMessage?: string;
}

function normalizeFingerprint(input?: string): string {
  if (!input) {
    return '';
  }

  return input.replace(/:/g, '').toUpperCase();
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function bytesToBinary(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return binary;
}

function bytesToBase64(bytes: Uint8Array): string {
  return globalThis.btoa(bytesToBinary(bytes));
}

function base64ToBytes(value: string): Uint8Array {
  const normalized = value.replace(/\s+/g, '');
  if (!normalized) {
    return new Uint8Array();
  }

  const binary = globalThis.atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

function base64ToHex(value: string): string {
  return bytesToHex(base64ToBytes(value));
}

function normalizeTimestamp(value?: number): string {
  if (!value || Number.isNaN(value)) {
    return '';
  }

  const milliseconds = value < 1_000_000_000_000 ? value * 1000 : value;
  return new Date(milliseconds).toISOString();
}

function derToPemFromBytes(der: Uint8Array): string {
  const base64 = bytesToBase64(der);
  const wrapped = base64.match(new RegExp(`.{1,${PEM_WRAP_WIDTH}}`, 'g'))?.join('\n') ?? '';

  if (!wrapped) {
    return '';
  }

  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
}

function derToPemFromArrayBuffer(der: ArrayBuffer): string {
  return derToPemFromBytes(new Uint8Array(der));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function readDerElement(bytes: Uint8Array, offset: number): DerElement {
  if (offset + 2 > bytes.length) {
    throw new Error('Invalid DER: truncated element header');
  }

  const tag = bytes[offset];
  const lengthByte = bytes[offset + 1];
  let length = 0;
  let lengthOctets = 0;

  if ((lengthByte & 0x80) === 0) {
    length = lengthByte;
  } else {
    const size = lengthByte & 0x7f;
    if (size === 0 || size > 4) {
      throw new Error('Invalid DER: unsupported length encoding');
    }
    if (offset + 2 + size > bytes.length) {
      throw new Error('Invalid DER: truncated long-form length');
    }

    lengthOctets = size;
    for (let index = 0; index < size; index += 1) {
      length = (length << 8) | bytes[offset + 2 + index];
    }
  }

  const valueStart = offset + 2 + lengthOctets;
  const valueEnd = valueStart + length;
  if (valueEnd > bytes.length) {
    throw new Error('Invalid DER: element extends beyond input');
  }

  return {
    tag,
    start: offset,
    end: valueEnd,
    valueStart,
    valueEnd,
  };
}

function readDerChildren(bytes: Uint8Array, element: DerElement): DerElement[] {
  if ((element.tag & 0x20) !== 0x20) {
    return [];
  }

  const children: DerElement[] = [];
  let offset = element.valueStart;
  while (offset < element.valueEnd) {
    const child = readDerElement(bytes, offset);
    children.push(child);
    offset = child.end;
  }

  if (offset !== element.valueEnd) {
    throw new Error('Invalid DER: child parsing ended at an unexpected boundary');
  }

  return children;
}

function decodeOid(bytes: Uint8Array, element: DerElement): string {
  if (element.tag !== 0x06 || element.valueStart >= element.valueEnd) {
    return '';
  }

  const values: number[] = [];
  const firstByte = bytes[element.valueStart];
  values.push(Math.floor(firstByte / 40));
  values.push(firstByte % 40);

  let currentValue = 0;
  for (let index = element.valueStart + 1; index < element.valueEnd; index += 1) {
    const byte = bytes[index];
    currentValue = (currentValue << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      values.push(currentValue);
      currentValue = 0;
    }
  }

  return values.join('.');
}

function decodeAsn1String(bytes: Uint8Array, element: DerElement): string {
  if (element.valueStart >= element.valueEnd) {
    return '';
  }

  if (element.tag === 0x1e) {
    const codeUnits: number[] = [];
    for (let index = element.valueStart; index + 1 < element.valueEnd; index += 2) {
      codeUnits.push((bytes[index] << 8) | bytes[index + 1]);
    }
    return String.fromCharCode(...codeUnits);
  }

  const content = bytes.slice(element.valueStart, element.valueEnd);
  return new TextDecoder().decode(content);
}

function parseAsn1Time(bytes: Uint8Array, element: DerElement): string {
  const raw = decodeAsn1String(bytes, element).trim();
  if (!raw) {
    return '';
  }

  if (element.tag === 0x17) {
    const utcMatch = raw.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
    if (!utcMatch) {
      return '';
    }

    const year = Number(utcMatch[1]);
    const fullYear = year >= 50 ? 1900 + year : 2000 + year;
    const month = Number(utcMatch[2]) - 1;
    const day = Number(utcMatch[3]);
    const hour = Number(utcMatch[4]);
    const minute = Number(utcMatch[5]);
    const second = Number(utcMatch[6] ?? '0');
    return new Date(Date.UTC(fullYear, month, day, hour, minute, second)).toISOString();
  }

  if (element.tag === 0x18) {
    const generalizedMatch = raw.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
    if (!generalizedMatch) {
      return '';
    }

    const year = Number(generalizedMatch[1]);
    const month = Number(generalizedMatch[2]) - 1;
    const day = Number(generalizedMatch[3]);
    const hour = Number(generalizedMatch[4]);
    const minute = Number(generalizedMatch[5]);
    const second = Number(generalizedMatch[6] ?? '0');
    return new Date(Date.UTC(year, month, day, hour, minute, second)).toISOString();
  }

  return '';
}

function parseDistinguishedName(bytes: Uint8Array, nameElement: DerElement): string {
  const rdnSets = readDerChildren(bytes, nameElement);
  const pairs: string[] = [];

  for (const rdnSet of rdnSets) {
    const attributes = readDerChildren(bytes, rdnSet);
    for (const attribute of attributes) {
      const values = readDerChildren(bytes, attribute);
      const oidElement = values[0];
      const valueElement = values[1];
      if (!oidElement || !valueElement) {
        continue;
      }

      const oid = decodeOid(bytes, oidElement);
      if (!oid) {
        continue;
      }

      const label = NAME_OID_LABELS[oid] ?? oid;
      const value = decodeAsn1String(bytes, valueElement).trim();
      if (value) {
        pairs.push(`${label}=${value}`);
      }
    }
  }

  return pairs.length > 0 ? pairs.join(', ') : UNKNOWN_VALUE;
}

function parseAlgorithmIdentifier(bytes: Uint8Array, algorithmElement: DerElement): string {
  const algorithmChildren = readDerChildren(bytes, algorithmElement);
  const oid = algorithmChildren[0] ? decodeOid(bytes, algorithmChildren[0]) : '';
  if (!oid) {
    return UNKNOWN_VALUE;
  }

  return SIGNATURE_ALGORITHM_OIDS[oid] ?? oid;
}

function parsePublicKeyDescription(bytes: Uint8Array, spkiElement: DerElement): string {
  const spkiChildren = readDerChildren(bytes, spkiElement);
  const algorithmElement = spkiChildren[0];
  if (!algorithmElement) {
    return UNKNOWN_VALUE;
  }

  const algorithmChildren = readDerChildren(bytes, algorithmElement);
  const oid = algorithmChildren[0] ? decodeOid(bytes, algorithmChildren[0]) : '';
  if (!oid) {
    return UNKNOWN_VALUE;
  }

  return PUBLIC_KEY_ALGORITHM_OIDS[oid] ?? oid;
}

function parseCertificateMeta(derBytes: Uint8Array): ParsedCertificateMeta {
  const certificate = readDerElement(derBytes, 0);
  if (certificate.tag !== 0x30) {
    throw new Error('Invalid DER: certificate is not a sequence');
  }

  const certificateChildren = readDerChildren(derBytes, certificate);
  const tbsElement = certificateChildren[0];
  if (!tbsElement) {
    throw new Error('Invalid DER: missing TBS certificate section');
  }

  const tbsChildren = readDerChildren(derBytes, tbsElement);
  const hasVersion = tbsChildren[0]?.tag === 0xa0;
  const serialIndex = hasVersion ? 1 : 0;
  const signatureIndex = hasVersion ? 2 : 1;
  const issuerIndex = hasVersion ? 3 : 2;
  const validityIndex = hasVersion ? 4 : 3;
  const subjectIndex = hasVersion ? 5 : 4;
  const spkiIndex = hasVersion ? 6 : 5;

  const serialElement = tbsChildren[serialIndex];
  const signatureElement = tbsChildren[signatureIndex];
  const issuerElement = tbsChildren[issuerIndex];
  const validityElement = tbsChildren[validityIndex];
  const subjectElement = tbsChildren[subjectIndex];
  const spkiElement = tbsChildren[spkiIndex];

  if (!serialElement || !issuerElement || !validityElement || !subjectElement || !spkiElement) {
    throw new Error('Invalid DER: missing required certificate fields');
  }

  const validityChildren = readDerChildren(derBytes, validityElement);
  const validFrom = validityChildren[0] ? parseAsn1Time(derBytes, validityChildren[0]) : '';
  const validTo = validityChildren[1] ? parseAsn1Time(derBytes, validityChildren[1]) : '';

  let serialNumber = bytesToHex(derBytes.slice(serialElement.valueStart, serialElement.valueEnd));
  serialNumber = serialNumber.replace(/^0+(?=[0-9A-F])/g, '');
  if (!serialNumber) {
    serialNumber = '00';
  }

  return {
    subject: parseDistinguishedName(derBytes, subjectElement),
    issuer: parseDistinguishedName(derBytes, issuerElement),
    validFrom,
    validTo,
    serialNumber,
    signatureAlgorithm: signatureElement
      ? parseAlgorithmIdentifier(derBytes, signatureElement)
      : UNKNOWN_VALUE,
    publicKey: parsePublicKeyDescription(derBytes, spkiElement),
    spkiDer: toArrayBuffer(derBytes.slice(spkiElement.start, spkiElement.end)),
  };
}

async function digestBytes(
  algorithm: AlgorithmIdentifier,
  input: BufferSource,
): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('Web Crypto API is unavailable');
  }

  const digestInput =
    input instanceof Uint8Array ? new Uint8Array(input) : new Uint8Array(input as ArrayBuffer);
  const digest = await subtle.digest(algorithm, digestInput);
  return new Uint8Array(digest);
}

async function digestHex(algorithm: AlgorithmIdentifier, input: BufferSource): Promise<string> {
  const digest = await digestBytes(algorithm, input);
  return bytesToHex(digest);
}

async function digestBase64(algorithm: AlgorithmIdentifier, input: BufferSource): Promise<string> {
  const digest = await digestBytes(algorithm, input);
  return bytesToBase64(digest);
}

function toCertificateRecord(
  certificate: FirefoxCertificateLike,
  index: number,
  isLeaf: boolean,
): CertificatePinEntry {
  const spkiSha256 = certificate.subjectPublicKeyInfoDigest?.sha256 ?? '';
  return {
    index,
    isLeaf,
    subject: certificate.subject ?? UNKNOWN_VALUE,
    issuer: certificate.issuer ?? UNKNOWN_VALUE,
    validFrom: normalizeTimestamp(certificate.validity?.start),
    validTo: normalizeTimestamp(certificate.validity?.end),
    serialNumber: certificate.serialNumber ?? '',
    sha1Fingerprint: normalizeFingerprint(certificate.fingerprint?.sha1),
    sha256Fingerprint: normalizeFingerprint(certificate.fingerprint?.sha256),
    spkiSha256,
    spkiSha256Hex: spkiSha256 ? base64ToHex(spkiSha256) : '',
    signatureAlgorithm: UNKNOWN_VALUE,
    publicKey: UNKNOWN_VALUE,
    pem: certificate.rawDER ? derToPemFromArrayBuffer(certificate.rawDER) : '',
  };
}

async function toChromiumCertificateRecord(
  certificateBase64: string,
  index: number,
  isLeaf: boolean,
): Promise<CertificatePinEntry> {
  const derBytes = base64ToBytes(certificateBase64);
  if (derBytes.byteLength === 0) {
    return {
      index,
      isLeaf,
      subject: UNKNOWN_VALUE,
      issuer: UNKNOWN_VALUE,
      validFrom: '',
      validTo: '',
      serialNumber: '',
      sha1Fingerprint: '',
      sha256Fingerprint: '',
      spkiSha256: '',
      spkiSha256Hex: '',
      signatureAlgorithm: UNKNOWN_VALUE,
      publicKey: UNKNOWN_VALUE,
      pem: '',
    };
  }

  let parsed: ParsedCertificateMeta | null = null;
  try {
    parsed = parseCertificateMeta(derBytes);
  } catch {
    parsed = null;
  }

  let spkiSha256 = '';
  let spkiSha256Hex = '';
  if (parsed?.spkiDer) {
    spkiSha256 = await digestBase64('SHA-256', parsed.spkiDer);
    spkiSha256Hex = await digestHex('SHA-256', parsed.spkiDer);
  }

  const derBuffer = toArrayBuffer(derBytes);
  const sha1Fingerprint = await digestHex('SHA-1', derBuffer);
  const sha256Fingerprint = await digestHex('SHA-256', derBuffer);

  return {
    index,
    isLeaf,
    subject: parsed?.subject ?? UNKNOWN_VALUE,
    issuer: parsed?.issuer ?? UNKNOWN_VALUE,
    validFrom: parsed?.validFrom ?? '',
    validTo: parsed?.validTo ?? '',
    serialNumber: parsed?.serialNumber ?? '',
    sha1Fingerprint,
    sha256Fingerprint,
    spkiSha256,
    spkiSha256Hex,
    signatureAlgorithm: parsed?.signatureAlgorithm ?? UNKNOWN_VALUE,
    publicKey: parsed?.publicKey ?? UNKNOWN_VALUE,
    pem: derToPemFromBytes(derBytes),
  };
}

export function fromFirefoxSecurityInfo(input: FirefoxSecurityInput): ProbeResult {
  const securityInfo = input.securityInfo as FirefoxSecurityInfoLike;
  const chain = securityInfo.certificates ?? [];
  const certificates = chain.map((certificate, index) =>
    toCertificateRecord(certificate, index + 1, index === 0),
  );
  const isDomainMismatch =
    securityInfo.isDomainMismatch === true || securityInfo.state?.includes('broken') === true;

  const warnings = buildWarnings(
    {
      certificates,
      target: {
        servername: input.servername,
      },
    },
    {
      expiringSoonDays: DEFAULT_EXPIRING_SOON_DAYS,
      hostnameMismatch: isDomainMismatch,
    },
  );

  return {
    target: {
      input: input.host,
      host: input.host,
      port: input.port,
      servername: input.servername,
    },
    connection: {
      ip: '',
      protocol: securityInfo.protocolVersion ?? UNKNOWN_VALUE,
      cipher: securityInfo.cipherSuite ?? UNKNOWN_VALUE,
      timeMs: 0,
      authorized: securityInfo.isUntrusted !== true,
      authorizationError: securityInfo.errorMessage,
    },
    certificates,
    warnings,
  };
}

export async function fromChromiumCertificateChain(
  input: ChromiumCertificateChainInput,
): Promise<ProbeResult> {
  const certificates = await Promise.all(
    (input.certificates ?? []).map((certificate, index) =>
      toChromiumCertificateRecord(certificate, index + 1, index === 0),
    ),
  );

  const warnings = buildWarnings(
    {
      certificates,
      target: {
        servername: input.servername,
      },
    },
    {
      expiringSoonDays: input.expiringSoonDays ?? DEFAULT_EXPIRING_SOON_DAYS,
      hostnameMismatch: input.hostnameMismatch,
    },
  );

  const authorized =
    typeof input.authorized === 'boolean'
      ? input.authorized
      : input.authorizationError
        ? false
        : true;

  return {
    target: {
      input: input.host,
      host: input.host,
      port: input.port,
      servername: input.servername,
    },
    connection: {
      ip: input.ip ?? '',
      protocol: input.protocol ?? UNKNOWN_VALUE,
      cipher: input.cipher ?? UNKNOWN_VALUE,
      timeMs: input.timeMs ?? 0,
      authorized,
      authorizationError: input.authorizationError,
    },
    certificates,
    warnings,
  };
}

export { buildWarnings, getCopyValue, toLegacyPins };
export { DEFAULT_EXPIRING_SOON_DAYS, SERIALIZATION_SCHEMA_VERSION };
