/**
 * Team key management for format-preserving tokenization (see src/scrub/fpe.ts).
 *
 * One team **master key** is the root of trust. Every detector category gets its
 * own **subkey** derived with HKDF-SHA-256 (RFC 5869), so a surrogate in one
 * category can never be decrypted under another (domain separation). Rotation is
 * expressed with a **key id** woven into the HKDF `info` parameter: bump the
 * current key id to start minting new surrogates while old key ids stay
 * available for restore-only.
 *
 * The master key lives only on this machine (`~/.aegis/team.key`, mode 0600) or
 * is supplied out-of-band via `AEGIS_TEAM_KEY` (base64). It is never transmitted;
 * exactly like the existing redaction key in crypto.ts.
 *
 * NOTE on the security of rotation: key ids derived from a single master give
 * *domain separation* per epoch, not *forward secrecy* — a leaked master derives
 * every epoch's subkeys. For true forward secrecy, drop an independent master per
 * epoch into `~/.aegis/keys/<keyId>.key`; those are picked up automatically and
 * take precedence over HKDF-from-the-single-master. This trade-off is documented
 * in docs/WHITEPAPER.md (C1 / key-compromise story).
 */
import { hkdfSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { aegisHome } from "./ca.js";

const KEY_LEN = 32;

/** Load or create the team master key. `AEGIS_TEAM_KEY` (base64) wins if set. */
export function loadOrCreateMasterKey(dir: string = aegisHome()): Buffer {
  const env = process.env.AEGIS_TEAM_KEY;
  if (env) {
    const b = Buffer.from(env.trim(), "base64");
    if (b.length >= 16) return b;
  }
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  const p = join(dir, "team.key");
  if (existsSync(p)) {
    const b = Buffer.from(readFileSync(p, "utf8").trim(), "base64");
    if (b.length === KEY_LEN) return b;
  }
  const key = randomBytes(KEY_LEN);
  writeFileSync(p, key.toString("base64"), { mode: 0o600 });
  return key;
}

/** Read any per-epoch master keys dropped in `~/.aegis/keys/<keyId>.key`. */
function loadEpochMasters(dir: string): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  const kd = join(dir, "keys");
  if (!existsSync(kd)) return out;
  for (const f of readdirSync(kd)) {
    if (!f.endsWith(".key")) continue;
    const keyId = f.slice(0, -4);
    const b = Buffer.from(readFileSync(join(kd, f), "utf8").trim(), "base64");
    if (b.length >= 16) out.set(keyId, b);
  }
  return out;
}

/** Derive a per-category subkey via HKDF-SHA-256, scoped by category and keyId. */
export function deriveSubkey(master: Buffer, category: string, keyId: string): Buffer {
  const salt = Buffer.from(`aegis-fpe/${category}`, "utf8");
  const info = Buffer.from(`kid=${keyId}`, "utf8");
  return Buffer.from(hkdfSync("sha256", master, salt, info, KEY_LEN));
}

/**
 * A keyring hands out cached per-category subkeys for the current key id, and can
 * still derive subkeys for older key ids so drifted/old surrogates restore.
 */
export class Keyring {
  readonly currentKeyId: string;
  private single: Buffer;
  private epochs: Map<string, Buffer>;
  private cache = new Map<string, Buffer>();

  constructor(dir: string = aegisHome(), currentKeyId = "k1") {
    this.single = loadOrCreateMasterKey(dir);
    this.epochs = loadEpochMasters(dir);
    this.currentKeyId = currentKeyId;
  }

  /** Master key for a given key id (epoch file if present, else the single master). */
  private masterFor(keyId: string): Buffer {
    return this.epochs.get(keyId) ?? this.single;
  }

  /** Cached subkey for `category` under `keyId` (defaults to the current key id). */
  subkey(category: string, keyId: string = this.currentKeyId): Buffer {
    const ck = `${category}#${keyId}`;
    let v = this.cache.get(ck);
    if (!v) {
      v = deriveSubkey(this.masterFor(keyId), category, keyId);
      this.cache.set(ck, v);
    }
    return v;
  }

  /** Key ids available for restore (current + any epoch files), newest-ish first. */
  knownKeyIds(): string[] {
    const ids = new Set<string>([this.currentKeyId, ...this.epochs.keys()]);
    return [...ids];
  }
}

export function makeKeyring(dir: string = aegisHome(), currentKeyId = "k1"): Keyring {
  return new Keyring(dir, currentKeyId);
}
