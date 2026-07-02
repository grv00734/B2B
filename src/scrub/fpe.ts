/**
 * Format-preserving encryption (FPE) — the primitive behind stateless,
 * "vault-free" restore (docs/WHITEPAPER.md, Algorithm 1).
 *
 * This is an FF1/FF3-family construction: an **alternating Feistel network** over
 * the value's own numeral domain (radix `r`, length `n`), whose round function is
 * a **keyed PRF built from HMAC-SHA-256**. It is a keyed permutation of
 * `Z_(r^n)` — same radix and length in, same out — so a 16-char key body becomes
 * a different 16-char key body, an IPv4 becomes a valid IPv4, etc.
 *
 * Why HMAC-SHA-256 rather than the exact AES round function of NIST SP 800-38G:
 * the alternating-Feistel structure and security argument are the FF3-1 design
 * (Bellare–Rogaway–Spies FFX; Morris–Rogaway–Stegers, "How to Encipher Messages
 * on a Small Domain"), but using HMAC as the PRF lets us validate every property
 * we rely on (bijection, exact round-trip, avalanche) in-repo with self-checking
 * tests, instead of claiming byte-exact NIST-vector interop we don't need — Aegis
 * is the only party that ever holds the key. This is stated honestly in the
 * whitepaper; if cross-tool interop is ever required, swap the PRF for AES-ECB
 * per the standard and validate against the published vectors.
 *
 * Invertibility: each round updates exactly one half from the *unchanged* other
 * half (mod r^m addition), so decrypt replays the rounds in reverse and subtracts
 * the identical PRF output. No swap, no fixpoint.
 */
import { createHmac } from "node:crypto";

/** Feistel rounds. Even count; ≥10 for small-domain security margin (FF1 uses 10). */
const ROUNDS = 10;

/** Numerals (most-significant first, base `radix`) → nonnegative bigint. */
function numeralsToBigInt(num: number[], radix: number): bigint {
  const R = BigInt(radix);
  let acc = 0n;
  for (const d of num) acc = acc * R + BigInt(d);
  return acc;
}

/** bigint → exactly `len` numerals (most-significant first, base `radix`). */
function bigIntToNumerals(value: bigint, radix: number, len: number): number[] {
  const R = BigInt(radix);
  const out = new Array<number>(len);
  let v = value;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v % R);
    v = v / R;
  }
  return out;
}

function pow(radix: number, e: number): bigint {
  return BigInt(radix) ** BigInt(e);
}

function bigIntToBuffer(v: bigint): Buffer {
  let hex = v.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}

function lenPrefixed(b: Buffer): Buffer {
  const l = Buffer.alloc(4);
  l.writeUInt32BE(b.length, 0);
  return Buffer.concat([l, b]);
}

/**
 * Round PRF: HMAC-SHA-256 keystream over (round, radix, m, tweak, other-half),
 * reduced into [0, radix^m). Extra keystream bytes keep the modulo bias negligible.
 */
function prf(
  subkey: Buffer,
  radix: number,
  tweak: Buffer,
  round: number,
  m: number,
  other: number[],
): bigint {
  const modulus = pow(radix, m);
  const header = Buffer.alloc(9);
  header.writeUInt8(round & 0xff, 0);
  header.writeUInt32BE(radix, 1);
  header.writeUInt32BE(m, 5);
  const otherBytes = bigIntToBuffer(numeralsToBigInt(other, radix));
  const msg = Buffer.concat([header, lenPrefixed(tweak), lenPrefixed(otherBytes)]);

  const need = bigIntToBuffer(modulus).length + 16; // + slack against modulo bias
  const chunks: Buffer[] = [];
  let got = 0;
  for (let ctr = 0; got < need; ctr++) {
    const ctrBuf = Buffer.alloc(4);
    ctrBuf.writeUInt32BE(ctr, 0);
    const h = createHmac("sha256", subkey).update(msg).update(ctrBuf).digest();
    chunks.push(h);
    got += h.length;
  }
  const stream = Buffer.concat(chunks).subarray(0, need);
  const big = BigInt("0x" + stream.toString("hex"));
  return big % modulus;
}

/** Encrypt a numeral array in place-preserving fashion (bijection over Z_(radix^n)). */
export function fpeEncryptNumerals(subkey: Buffer, radix: number, tweak: Buffer, x: number[]): number[] {
  const n = x.length;
  const R = BigInt(radix);
  if (n === 0) return [];
  if (n === 1) {
    const f = prf(subkey, radix, tweak, 0, 1, []);
    return [Number((BigInt(x[0]!) + f) % R)];
  }
  const u = Math.floor(n / 2);
  const v = n - u;
  const modU = pow(radix, u);
  const modV = pow(radix, v);
  let A = numeralsToBigInt(x.slice(0, u), radix);
  let B = numeralsToBigInt(x.slice(u), radix);
  for (let i = 0; i < ROUNDS; i++) {
    if (i % 2 === 0) {
      const f = prf(subkey, radix, tweak, i, u, bigIntToNumerals(B, radix, v));
      A = (A + f) % modU;
    } else {
      const f = prf(subkey, radix, tweak, i, v, bigIntToNumerals(A, radix, u));
      B = (B + f) % modV;
    }
  }
  return [...bigIntToNumerals(A, radix, u), ...bigIntToNumerals(B, radix, v)];
}

/** Inverse of {@link fpeEncryptNumerals}. */
export function fpeDecryptNumerals(subkey: Buffer, radix: number, tweak: Buffer, y: number[]): number[] {
  const n = y.length;
  const R = BigInt(radix);
  if (n === 0) return [];
  if (n === 1) {
    const f = prf(subkey, radix, tweak, 0, 1, []);
    return [Number(((BigInt(y[0]!) - f) % R + R) % R)];
  }
  const u = Math.floor(n / 2);
  const v = n - u;
  const modU = pow(radix, u);
  const modV = pow(radix, v);
  let A = numeralsToBigInt(y.slice(0, u), radix);
  let B = numeralsToBigInt(y.slice(u), radix);
  for (let i = ROUNDS - 1; i >= 0; i--) {
    if (i % 2 === 0) {
      const f = prf(subkey, radix, tweak, i, u, bigIntToNumerals(B, radix, v));
      A = ((A - f) % modU + modU) % modU;
    } else {
      const f = prf(subkey, radix, tweak, i, v, bigIntToNumerals(A, radix, u));
      B = ((B - f) % modV + modV) % modV;
    }
  }
  return [...bigIntToNumerals(A, radix, u), ...bigIntToNumerals(B, radix, v)];
}

/** Encrypt a string over a fixed `alphabet` (each char must be in it). */
export function encryptOverAlphabet(subkey: Buffer, alphabet: string, tweak: Buffer, s: string): string {
  const radix = alphabet.length;
  const idx = [...s].map((c) => alphabet.indexOf(c));
  if (idx.some((i) => i < 0)) throw new Error("fpe: character not in alphabet");
  const enc = fpeEncryptNumerals(subkey, radix, tweak, idx);
  return enc.map((i) => alphabet.charAt(i)).join("");
}

/** Inverse of {@link encryptOverAlphabet}. */
export function decryptOverAlphabet(subkey: Buffer, alphabet: string, tweak: Buffer, s: string): string {
  const radix = alphabet.length;
  const idx = [...s].map((c) => alphabet.indexOf(c));
  if (idx.some((i) => i < 0)) throw new Error("fpe: character not in alphabet");
  const dec = fpeDecryptNumerals(subkey, radix, tweak, idx);
  return dec.map((i) => alphabet.charAt(i)).join("");
}
