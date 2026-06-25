/**
 * Certificate authority for the transparent (MITM) proxy.
 *
 * On first use we generate a self-signed root CA and persist it under the Aegis
 * home dir. For each intercepted host we mint a short leaf certificate signed by
 * that root, so the client sees a valid certificate chain *once it trusts our
 * root CA*. A single leaf key is reused across hosts (only the cheap signing
 * step runs per host), which keeps interception fast.
 *
 * The root private key never leaves this machine. Traffic is only ever decrypted
 * in memory inside the proxy; it is re-encrypted to the real provider with normal
 * certificate verification.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import * as tls from "node:tls";
import forge from "node-forge";

export interface Pem {
  cert: string;
  key: string;
}

export function aegisHome(): string {
  return process.env.AEGIS_HOME ?? join(homedir(), ".aegis");
}

function randomSerial(): string {
  // Positive 16-byte hex serial.
  return "00" + forge.util.bytesToHex(forge.random.getBytesSync(16));
}

const CA_SUBJECT = [
  { name: "commonName", value: "Aegis DLP Guard Root CA" },
  { name: "organizationName", value: "Aegis" },
];

function buildCA(): Pem {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerial();
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
  cert.setSubject(CA_SUBJECT);
  cert.setIssuer(CA_SUBJECT);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, digitalSignature: true, critical: true },
    { name: "subjectKeyIdentifier" },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    cert: forge.pki.certificateToPem(cert),
    key: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

export class CertAuthority {
  readonly dir: string;
  readonly caCertPem: string;
  readonly caKeyPem: string;
  /** Shared leaf private key (PEM) used for every minted host certificate. */
  readonly leafKeyPem: string;

  private caCert: forge.pki.Certificate;
  private caKey: forge.pki.rsa.PrivateKey;
  private leafPublicKey: forge.pki.PublicKey;
  private contexts = new Map<string, tls.SecureContext>();

  constructor(dir: string = aegisHome()) {
    this.dir = dir;
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });

    const caCertPath = join(dir, "ca.crt");
    const caKeyPath = join(dir, "ca.key");
    const leafKeyPath = join(dir, "leaf.key");

    if (existsSync(caCertPath) && existsSync(caKeyPath)) {
      this.caCertPem = readFileSync(caCertPath, "utf8");
      this.caKeyPem = readFileSync(caKeyPath, "utf8");
    } else {
      const ca = buildCA();
      this.caCertPem = ca.cert;
      this.caKeyPem = ca.key;
      writeFileSync(caCertPath, ca.cert, { mode: 0o644 });
      writeFileSync(caKeyPath, ca.key, { mode: 0o600 });
    }

    if (existsSync(leafKeyPath)) {
      this.leafKeyPem = readFileSync(leafKeyPath, "utf8");
    } else {
      const leafKeys = forge.pki.rsa.generateKeyPair(2048);
      this.leafKeyPem = forge.pki.privateKeyToPem(leafKeys.privateKey);
      writeFileSync(leafKeyPath, this.leafKeyPem, { mode: 0o600 });
    }

    this.caCert = forge.pki.certificateFromPem(this.caCertPem);
    this.caKey = forge.pki.privateKeyFromPem(this.caKeyPem) as forge.pki.rsa.PrivateKey;
    // Derive the leaf public key from the shared leaf private key.
    const leafPriv = forge.pki.privateKeyFromPem(this.leafKeyPem) as forge.pki.rsa.PrivateKey;
    this.leafPublicKey = forge.pki.setRsaPublicKey(leafPriv.n, leafPriv.e);
  }

  get caCertPath(): string {
    return join(this.dir, "ca.crt");
  }

  /** Mint (or reuse) a TLS secure context presenting a cert valid for `host`. */
  contextFor(host: string): tls.SecureContext {
    const cached = this.contexts.get(host);
    if (cached) return cached;
    const leafPem = this.mintLeaf(host);
    const ctx = tls.createSecureContext({
      key: this.leafKeyPem,
      cert: `${leafPem}\n${this.caCertPem}`,
    });
    this.contexts.set(host, ctx);
    return ctx;
  }

  /** The leaf certificate PEM for a host (signed by our root). */
  mintLeaf(host: string): string {
    const cert = forge.pki.createCertificate();
    cert.publicKey = this.leafPublicKey;
    cert.serialNumber = randomSerial();
    cert.validity.notBefore = new Date();
    cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    cert.setSubject([{ name: "commonName", value: host }]);
    cert.setIssuer(this.caCert.subject.attributes);
    cert.setExtensions([
      { name: "basicConstraints", cA: false },
      { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
      { name: "extKeyUsage", serverAuth: true },
      { name: "subjectAltName", altNames: [{ type: 2, value: host }] }, // type 2 = DNS
    ]);
    cert.sign(this.caKey, forge.md.sha256.create());
    return forge.pki.certificateToPem(cert);
  }
}

/** OS-specific instructions for trusting the root CA. */
export function trustInstructions(caPath: string): string {
  return [
    `Trust the Aegis root CA so apps accept the guard's certificates:`,
    ``,
    `  Linux  (system store):`,
    `    sudo cp "${caPath}" /usr/local/share/ca-certificates/aegis.crt && sudo update-ca-certificates`,
    ``,
    `  macOS:`,
    `    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${caPath}"`,
    ``,
    `  Windows (PowerShell as admin):`,
    `    Import-Certificate -FilePath "${caPath}" -CertStoreLocation Cert:\\LocalMachine\\Root`,
    ``,
    `  Node-based agents (Claude Code, etc.) — lighter touch, no admin:`,
    `    export NODE_EXTRA_CA_CERTS="${caPath}"`,
  ].join("\n");
}
