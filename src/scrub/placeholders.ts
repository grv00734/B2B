/**
 * The Vault holds the mapping between real confidential values and the opaque
 * placeholders that take their place in outbound traffic.
 *
 * SECURITY: a Vault is created fresh per request and lives only in memory for
 * the duration of that request/response pair. Real values are never written to
 * disk, never logged, and never sent upstream.
 */

const PLACEHOLDER_RE = /\[\[REDACTED:[A-Z0-9_]+:\d+\]\]/g;

export class Vault {
  private counter = 0;
  /** real value -> placeholder (so repeated values map to the same token). */
  private forward = new Map<string, string>();
  /** placeholder -> real value (for restoration). */
  private backward = new Map<string, string>();

  /** Return a stable placeholder for a given real value + type. */
  placeholderFor(value: string, type: string): string {
    const existing = this.forward.get(value);
    if (existing) return existing;

    const token = `[[REDACTED:${type}:${++this.counter}]]`;
    this.forward.set(value, token);
    this.backward.set(token, value);
    return token;
  }

  /** Swap any placeholders found in `text` back to their real values. */
  restore(text: string): string {
    if (this.backward.size === 0) return text;
    return text.replace(PLACEHOLDER_RE, (token) => this.backward.get(token) ?? token);
  }

  get size(): number {
    return this.backward.size;
  }

  /** Recursively restore placeholders in every string within a JSON-like value. */
  restoreDeep<T>(value: T): T {
    if (this.backward.size === 0) return value;
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
