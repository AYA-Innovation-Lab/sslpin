export type CopyKind = 'spki' | 'sha256' | 'pem';

export interface InspectTlsHostOptions {
  input: string;
  port?: number;
  timeoutMs?: number;
  servername?: string;
  leafOnly?: boolean;
  expiringSoonDays?: number;
}

export interface ProbeOptions {
  port?: number;
  timeoutMs?: number;
  servername?: string;
  leafOnly?: boolean;
  expiringSoonDays?: number;
}

export interface InspectionWarning {
  code: 'CERT_EXPIRED' | 'CERT_EXPIRING_SOON' | 'HOSTNAME_MISMATCH' | 'MISSING_CERTIFICATE_DATA';
  message: string;
  certIndex: number;
  severity: 'warning';
}

export interface CertificatePinEntry {
  index: number;
  isLeaf: boolean;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  sha1Fingerprint: string;
  sha256Fingerprint: string;
  spkiSha256: string;
  spkiSha256Hex: string;
  signatureAlgorithm: string;
  publicKey: string;
  pem: string;
}

export interface TlsConnectionSummary {
  ip: string;
  protocol: string;
  cipher: string;
  timeMs: number;
  authorized: boolean;
  authorizationError?: string;
}

export interface CertificateInspectionResult {
  target: {
    input: string;
    host: string;
    port: number;
    servername: string;
  };
  connection: TlsConnectionSummary;
  certificates: CertificatePinEntry[];
  warnings: InspectionWarning[];
}

export interface SerializableInspectionResult {
  host: string;
  ip: string;
  port: number;
  tlsVersion: string;
  cipher: string;
  durationMs: number;
  warnings: InspectionWarning[];
  certificates: CertificatePinEntry[];
}

export interface BuildWarningsOptions {
  expiringSoonDays?: number;
  hostnameMismatch?: boolean;
}

export interface WarningBuildInput {
  certificates: CertificatePinEntry[];
  target?: {
    servername?: string;
  };
}

export type ProbeWarning = InspectionWarning;
export type CertificateRecord = CertificatePinEntry;
export type ProbeResult = CertificateInspectionResult;

export interface LegacyPinRecord {
  index: number;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  sha1Fingerprint: string;
  sha256Fingerprint: string;
  spkiSha256: string;
  spkiSha256Hex: string;
  signatureAlgorithm: string;
  publicKey: string;
  certificate: string;
}

export interface LegacyProbeResult {
  pins: LegacyPinRecord[];
  ip: string;
  port: number;
  tlsVersion: string;
  cipher: string;
  time: number;
  status: 'OK';
  dataSize: number;
}

export interface FirefoxSecurityInput {
  host: string;
  port: number;
  servername: string;
  securityInfo: unknown;
}

export interface ChromiumCertificateChainInput {
  host: string;
  port: number;
  servername: string;
  certificates: string[];
  ip?: string;
  protocol?: string;
  cipher?: string;
  timeMs?: number;
  authorized?: boolean;
  authorizationError?: string;
  hostnameMismatch?: boolean;
  expiringSoonDays?: number;
}
