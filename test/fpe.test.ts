import { describe, it, expect } from "vitest";
import {
  fpeEncryptNumerals,
  fpeDecryptNumerals,
  encryptOverAlphabet,
  decryptOverAlphabet,
} from "../src/scrub/fpe.js";
import { deriveSubkey } from "../src/keys.js";

const master = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
const key = deriveSubkey(master, "test", "k1");
const tweak = Buffer.from("tweak", "utf8");

describe("fpe numerals", () => {
  it("round-trips across radices and lengths", () => {
    for (const radix of [2, 10, 16, 36, 62, 256]) {
      for (const n of [1, 2, 3, 4, 7, 8, 16]) {
        const x = Array.from({ length: n }, (_, i) => (i * 7 + 3) % radix);
        const enc = fpeEncryptNumerals(key, radix, tweak, x);
        expect(enc).toHaveLength(n);
        expect(enc.every((d) => d >= 0 && d < radix)).toBe(true);
        const dec = fpeDecryptNumerals(key, radix, tweak, enc);
        expect(dec).toEqual(x);
      }
    }
  });

  it("is a permutation (bijective) over a small domain", () => {
    // radix 10, length 4 -> 10_000 elements; assert no collisions.
    const seen = new Set<string>();
    for (let v = 0; v < 10000; v++) {
      const digits = [Math.floor(v / 1000) % 10, Math.floor(v / 100) % 10, Math.floor(v / 10) % 10, v % 10];
      const enc = fpeEncryptNumerals(key, 10, tweak, digits).join("");
      seen.add(enc);
    }
    expect(seen.size).toBe(10000);
  });

  it("changes ciphertext when the tweak changes (domain separation)", () => {
    const x = [1, 2, 3, 4, 5, 6];
    const a = fpeEncryptNumerals(key, 10, Buffer.from("A"), x).join("");
    const b = fpeEncryptNumerals(key, 10, Buffer.from("B"), x).join("");
    expect(a).not.toBe(b);
  });

  it("changes ciphertext when the key changes", () => {
    const x = [1, 2, 3, 4, 5, 6];
    const k2 = deriveSubkey(master, "test", "k2");
    const a = fpeEncryptNumerals(key, 10, tweak, x).join("");
    const b = fpeEncryptNumerals(k2, 10, tweak, x).join("");
    expect(a).not.toBe(b);
  });

  it("avalanches: a one-digit input change flips most output digits", () => {
    const x = [3, 1, 4, 1, 5, 9, 2, 6];
    const y = [...x];
    y[0] = (y[0]! + 1) % 10;
    const ex = fpeEncryptNumerals(key, 10, tweak, x);
    const ey = fpeEncryptNumerals(key, 10, tweak, y);
    const differing = ex.filter((d, i) => d !== ey[i]).length;
    expect(differing).toBeGreaterThanOrEqual(4); // > half of 8 positions typically differ
  });
});

describe("fpe over alphabet", () => {
  it("preserves length and alphabet, and round-trips", () => {
    const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const s = "HELLO123WORLD456";
    const enc = encryptOverAlphabet(key, alphabet, tweak, s);
    expect(enc).toHaveLength(s.length);
    expect([...enc].every((c) => alphabet.includes(c))).toBe(true);
    expect(enc).not.toBe(s);
    expect(decryptOverAlphabet(key, alphabet, tweak, enc)).toBe(s);
  });

  it("rejects characters outside the alphabet", () => {
    expect(() => encryptOverAlphabet(key, "abc", tweak, "xyz")).toThrow();
  });
});
