import crypto from "node:crypto";
import tls from "node:tls";
import dns from "dns/promises";

// @ts-ignore
import forge from 'node-forge';

export interface PeerCertificateEx extends tls.PeerCertificate {
  issuerCertificate?: PeerCertificateEx;
}

export interface CertPin {
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

export interface SSLPingResult {
  pins: CertPin[];
  ip: string;
  port: number;
  tlsVersion: string;
  cipher: string;
  time: number;
  status: string;
  dataSize: number;
}

/**
 * Convert DER buffer to PEM string
 */
export function derToPem(der: Buffer): string {
  const base64 = der.toString("base64").match(/.{1,64}/g)?.join("\n");
  if (!base64) throw new Error("Invalid DER buffer");
  return `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----\n`;
}

/**
 * Ping SSL for domain and get SHA256 pins (SPKI)
 */
export async function sslPingDomain(domain: string): Promise<SSLPingResult> {
  const { address } = await dns.lookup(domain);
  const port = 443;
  const startTime = Date.now();

  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: address, port, servername: domain, rejectUnauthorized: false, timeout: 60000 },
      () => {
        const endTime = Date.now();
        const time = endTime - startTime;
        const tlsVersion = socket.getProtocol() || 'TLS';
        const cipher = socket.getCipher().name;

        const chain = socket.getPeerCertificate(true) as PeerCertificateEx;
        if (!chain || !chain.raw) return reject(new Error("No certificate chain"));

        const pins: CertPin[] = [];
        let current: PeerCertificateEx | undefined = chain;
        let index = 1;

        while (current) {
          try {
            const pem = derToPem(current.raw);
            const x509 = new crypto.X509Certificate(pem);

            // Extract SPKI DER from public key
            const spkiDer = x509.publicKey.export({ type: "spki", format: "der" });

            // Calculate fingerprints
            const sha1Fingerprint = crypto.createHash("sha1").update(current.raw).digest("hex").toUpperCase();
            const sha256Fingerprint = crypto.createHash("sha256").update(current.raw).digest("hex").toUpperCase();
            const spkiSha256 = crypto.createHash("sha256").update(spkiDer).digest("base64");
            const spkiSha256Hex = crypto.createHash("sha256").update(spkiDer).digest("hex").toUpperCase();

            // Parse using Node.js built-in X509Certificate
            const sigAlg = forge.pki.oids[x509.signatureAlgorithm] || x509.signatureAlgorithm || 'Unknown';
            const pubKey = x509.publicKey;
            const keyType = pubKey.asymmetricKeyType || 'unknown';
            const keySizeNum = (pubKey as any).asymmetricKeySize;
            let keySize = keySizeNum ? keySizeNum.toString() : 'Unknown';
            let publicKey = keyType === 'rsa' ? `${keyType.toUpperCase()} ${keySize}` :
                           keyType === 'ec' ? `${keyType.toUpperCase()} ${keySize === 'Unknown' ? 'ECC' : keySize}` :
                           `${keyType.toUpperCase()} ${keySize}`;
            let certificate = pem;

            pins.push({
              index,
              subject: current.subject.CN,
              issuer: current.issuer.CN,
              validFrom: current.valid_from,
              validTo: current.valid_to,
              serialNumber: current.serialNumber,
              sha1Fingerprint,
              sha256Fingerprint,
              spkiSha256,
              spkiSha256Hex,
              signatureAlgorithm: sigAlg,
              publicKey,
              certificate
            });
          } catch (err) {
            reject(err);
            return;
          }

          // Stop if there is no more issuer (end of chain)
          if (!current.issuerCertificate || current.issuerCertificate === current) break;
          current = current.issuerCertificate;
          index++;
        }

        socket.end();
        resolve({
          pins,
          ip: address,
          port,
          tlsVersion,
          cipher,
          time,
          status: "OK",
          dataSize: 64
        });
      }
    );

    socket.on("error", reject);
  });
}
