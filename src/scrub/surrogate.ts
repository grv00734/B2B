/**
 * Type-aware surrogate formatters (docs/WHITEPAPER.md, C1 / Algorithm 1).
 *
 * Each formatter maps a detected value to a *same-shape* surrogate by
 * format-preserving encryption of the value's variable payload, keeping the
 * structural skeleton (prefixes, separators, length) intact and fixing any
 * validators (octet ranges, etc.). Because the transform is a keyed permutation,
 * restore is decryption — no per-request state required.
 *
 * Phase 1 ships three categories end-to-end: AWS access keys, generic hex tokens,
 * and IPv4 addresses. Others fall back to index placeholders in the Vault, so
 * nothing regresses when a formatter is missing.
 *
 * Reversibility note (IPv4): a reversible map must be injective, so the surrogate
 * IPv4 is encrypted over the full 2^32 domain (a valid dotted-quad, possibly a
 * routable-looking address). Clamping into RFC 5737 TEST-NET ranges — proposed in
 * the spec — is *not* injective (only 768 addresses) and so cannot be the
 * reversible path; it belongs to a future non-reversible "mask" mode. This is a
 * deliberate, documented trade-off in favor of round-trip correctness.
 */
import type { AegisConfig } from "../types.js";
import { aegisHome } from "../ca.js";
import { loadOrCreateKey } from "../crypto.js";
import { Keyring, makeKeyring } from "../keys.js";
import { Vault, type Tokenizer } from "./placeholders.js";
import { encryptOverAlphabet, decryptOverAlphabet, fpeEncryptNumerals, fpeDecryptNumerals } from "./fpe.js";

const BASE36_UP = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const HEX_LOWER = "0123456789abcdef";
const AWS_PREFIXES = ["AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA"];

export interface SurrogateFormatter {
  /** Subkey scope (HKDF category). */
  category: string;
  /** Whether this formatter handles a detected value of the given detector type. */
  matches(value: string, type: string): boolean;
  /** Recognize a standalone candidate token during stateless restore. */
  grammar: RegExp;
  /** Produce a format-preserving surrogate. */
  encode(value: string, ring: Keyring): string;
  /** Reverse a candidate token, or null if it is not a well-formed surrogate. */
  decode(token: string, ring: Keyring): string | null;
}

/** AWS access key: `AKIA`+16 chars of [0-9A-Z]. Prefix kept; body FPE'd over base36. */
const awsKey: SurrogateFormatter = {
  category: "aws_key",
  grammar: new RegExp(`\\b(?:${AWS_PREFIXES.join("|")})[0-9A-Z]{16}\\b`, "g"),
  matches: (_v, t) => t === "AWS_ACCESS_KEY",
  encode(value, ring) {
    const prefix = value.slice(0, 4);
    const body = value.slice(4);
    const tweak = Buffer.from(`aws:${prefix}`, "utf8");
    return prefix + encryptOverAlphabet(ring.subkey("aws_key"), BASE36_UP, tweak, body);
  },
  decode(token, ring) {
    const prefix = token.slice(0, 4);
    const body = token.slice(4);
    if (!AWS_PREFIXES.includes(prefix) || body.length !== 16 || !/^[0-9A-Z]{16}$/.test(body)) return null;
    const tweak = Buffer.from(`aws:${prefix}`, "utf8");
    return prefix + decryptOverAlphabet(ring.subkey("aws_key"), BASE36_UP, tweak, body);
  },
};

/** IPv4: four octets FPE'd over the full 2^32 domain; output is a valid dotted-quad. */
const ipv4: SurrogateFormatter = {
  category: "ipv4",
  grammar: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  matches: (_v, t) => t === "IPV4",
  encode(value, ring) {
    const octets = value.split(".").map((o) => parseInt(o, 10));
    const tweak = Buffer.from("ipv4", "utf8");
    const enc = fpeEncryptNumerals(ring.subkey("ipv4"), 256, tweak, octets);
    return enc.join(".");
  },
  decode(token, ring) {
    const parts = token.split(".");
    if (parts.length !== 4) return null;
    const octets = parts.map((o) => parseInt(o, 10));
    if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
    const tweak = Buffer.from("ipv4", "utf8");
    const dec = fpeDecryptNumerals(ring.subkey("ipv4"), 256, tweak, octets);
    return dec.join(".");
  },
};

/**
 * Generic hex token (≥16 chars, uniform case). Encrypted over base16, case
 * preserved. Mixed-case runs are declined (returned as no-match) so the stateless
 * round-trip stays exact; those still redact via the Vault fallback.
 */
const hexToken: SurrogateFormatter = {
  category: "hex",
  grammar: /\b(?:[0-9a-f]{16,}|[0-9A-F]{16,})\b/g,
  matches: (v) => /^[0-9a-f]{16,}$/.test(v) || /^[0-9A-F]{16,}$/.test(v),
  encode(value, ring) {
    const upper = /^[0-9A-F]+$/.test(value);
    const tweak = Buffer.from(`hex:${value.length}`, "utf8");
    const enc = encryptOverAlphabet(ring.subkey("hex"), HEX_LOWER, tweak, value.toLowerCase());
    return upper ? enc.toUpperCase() : enc;
  },
  decode(token, ring) {
    if (!/^[0-9a-f]{16,}$/.test(token) && !/^[0-9A-F]{16,}$/.test(token)) return null;
    const upper = /^[0-9A-F]+$/.test(token);
    const tweak = Buffer.from(`hex:${token.length}`, "utf8");
    const dec = decryptOverAlphabet(ring.subkey("hex"), HEX_LOWER, tweak, token.toLowerCase());
    return upper ? dec.toUpperCase() : dec;
  },
};

/** Registry, ordered most-specific first (AWS keys are hex-ish, so they win). */
export const FORMATTERS: SurrogateFormatter[] = [awsKey, ipv4, hexToken];

/** Tokenizer the Vault uses to mint/reverse format-preserving surrogates. */
export class SurrogateTokenizer implements Tokenizer {
  constructor(private ring: Keyring) {}

  encode(value: string, type: string): string | null {
    for (const f of FORMATTERS) {
      if (f.matches(value, type)) {
        try {
          return f.encode(value, this.ring);
        } catch {
          return null;
        }
      }
    }
    return null;
  }

  /** Stateless single-token decode (phase 2 adds a mini-MAC to reject non-ours). */
  decodeToken(token: string): string | null {
    for (const f of FORMATTERS) {
      try {
        const r = f.decode(token, this.ring);
        if (r !== null) return r;
      } catch {
        /* try next formatter */
      }
    }
    return null;
  }
}

/** Effective tokenization mode, honoring the legacy `encryption.enabled` flag. */
export function resolveTokenMode(cfg: AegisConfig): "placeholder" | "encrypt" | "fpt" {
  const m = cfg.tokenization?.mode;
  if (m === "placeholder" || m === "encrypt" || m === "fpt") return m;
  if (cfg.encryption?.enabled) return "encrypt";
  return "placeholder";
}

/**
 * Build a factory that mints fresh Vaults configured per `cfg`. The keyring/
 * tokenizer (and any deterministic subkeys) are created once and shared across
 * every Vault the factory produces, so identical secrets map to identical
 * surrogates for the whole process lifetime.
 */
export function makeVaultFactory(cfg: AegisConfig): () => Vault {
  const mode = resolveTokenMode(cfg);
  if (mode === "fpt") {
    const ring = makeKeyring(aegisHome(), cfg.tokenization?.keyId ?? "k1");
    const tokenizer = new SurrogateTokenizer(ring);
    return () => new Vault({ mode: "fpt", tokenizer });
  }
  if (mode === "encrypt") {
    const key = loadOrCreateKey();
    return () => new Vault({ mode: "encrypt", key });
  }
  return () => new Vault();
}
