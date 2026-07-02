/**
 * The Vault holds the mapping between real confidential values and the opaque
 * tokens that take their place in outbound traffic.
 *
 * Three token strategies:
 *  - `placeholder` (default): a stable index placeholder `[[REDACTED:TYPE:N]]`
 *    (mapping kept in memory for this request).
 *  - `encrypt`: an AES-256-GCM token `[[AEGIS:<ciphertext>]]`. The ciphertext
 *    carries the value, so restoration works by decryption — statelessly, even
 *    across restarts/instances.
 *  - `fpt`: a **format-preserving surrogate** (see scrub/surrogate.ts) — a
 *    same-shape fake value that keeps the model's utility and, being a keyed
 *    permutation, also restores statelessly.
 *
 * SECURITY: a Vault is created fresh per request and lives only in memory for
 * the duration of that request/response pair. Real values are never written to
 * disk, never logged, and never sent upstream (only placeholders/ciphertext are).
 */
import { encrypt, decrypt, AEGIS_TOKEN_RE } from "../crypto.js";

const PLACEHOLDER_RE = /\[\[REDACTED:[A-Z0-9_]+:\d+\]\]/g;
/** Matches either token kind, for the fast map-based restore pass. */
const ANY_TOKEN_RE = /\[\[(?:REDACTED:[A-Z0-9_]+:\d+|AEGIS:[A-Za-z0-9_-]+)\]\]/g;

export type TokenMode = "placeholder" | "encrypt" | "fpt";

/** Minimal surrogate tokenizer the Vault depends on (implemented in surrogate.ts). */
export interface Tokenizer {
  /** Return a surrogate for `value`/`type`, or null if no formatter applies. */
  encode(value: string, type: string): string | null;
  /** Stateless reverse of a single token, or null if it is not a surrogate. */
  decodeToken?(token: string): string | null;
}

export interface VaultOptions {
  mode?: TokenMode;
  /** Required for `encrypt` mode. */
  key?: Buffer;
  /** Required for `fpt` mode. */
  tokenizer?: Tokenizer;
}

export class Vault {
  private counter = 0;
  /** real value -> token (so repeated values map to the same token). */
  private forward = new Map<string, string>();
  /** token -> real value (for restoration). */
  private backward = new Map<string, string>();
  private mode: TokenMode;
  private key?: Buffer;
  private tokenizer?: Tokenizer;

  /**
   * Back-compat: `new Vault()` = index placeholders, `new Vault(key)` = encryption
   * mode. New code passes options to select `fpt` (format-preserving) mode.
   */
  constructor(opt?: Buffer | VaultOptions) {
    if (Buffer.isBuffer(opt)) {
      this.mode = "encrypt";
      this.key = opt;
    } else if (opt) {
      this.mode = opt.mode ?? "placeholder";
      this.key = opt.key;
      this.tokenizer = opt.tokenizer;
    } else {
      this.mode = "placeholder";
    }
  }

  private indexPlaceholder(type: string): string {
    return `[[REDACTED:${type}:${++this.counter}]]`;
  }

  /** Return a stable token for a given real value + type. */
  placeholderFor(value: string, type: string): string {
    const existing = this.forward.get(value);
    if (existing) return existing;

    let token: string;
    if (this.mode === "fpt" && this.tokenizer) {
      // Fall back to an index placeholder when no format-preserving formatter applies.
      token = this.tokenizer.encode(value, type) ?? this.indexPlaceholder(type);
    } else if (this.mode === "encrypt" && this.key) {
      token = `[[AEGIS:${encrypt(value, this.key)}]]`;
    } else {
      token = this.indexPlaceholder(type);
    }
    this.forward.set(value, token);
    this.backward.set(token, value);
    return token;
  }

  /** Swap any tokens found in `text` back to their real values. */
  restore(text: string): string {
    if (this.backward.size === 0 && !this.key) return text;
    let out = text;
    // 1) fast path: exact bracketed tokens we minted this request.
    if (this.backward.size > 0) {
      out = out.replace(ANY_TOKEN_RE, (t) => this.backward.get(t) ?? t);
      // fpt surrogates are bare (no `[[…]]` marker): swap known ones literally,
      // longest-first so a shorter surrogate can't clobber a longer one.
      if (this.mode === "fpt") {
        for (const surrogate of [...this.backward.keys()].sort((a, b) => b.length - a.length)) {
          if (surrogate.startsWith("[[")) continue; // already handled above
          out = out.split(surrogate).join(this.backward.get(surrogate)!);
        }
      }
    }
    // 2) stateless path: decrypt any remaining encrypted tokens.
    if (this.key) {
      out = out.replace(AEGIS_TOKEN_RE, (m, blob: string) => decrypt(blob, this.key!) ?? m);
    }
    return out;
  }

  get size(): number {
    return this.backward.size;
  }

  /** Whether this vault should process responses (has entries or a key). */
  get active(): boolean {
    return this.backward.size > 0 || !!this.key;
  }

  /** Recursively restore tokens in every string within a JSON-like value. */
  restoreDeep<T>(value: T): T {
    if (this.backward.size === 0 && !this.key) return value;
    if (typeof value === "string") return this.restore(value) as unknown as T;
    if (Array.isArray(value)) return value.map((v) => this.restoreDeep(v)) as unknown as T;
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = this.restoreDeep(v);
      }
      return out as unknown as T;
    }
    return value;
  }
}

export { PLACEHOLDER_RE };
