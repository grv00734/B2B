# Aegis Research Extensions — Design Whitepaper

**Reversible, utility-preserving redaction for LLM traffic, and privacy-preserving fleet telemetry.**

Status: **DESIGN — awaiting approval before implementation.**
Scope: three additions to Aegis, all fully local / offline / no-API-key, consistent with the
existing engine in [`src/scrub/`](../src/scrub/).

---

## 0. The research problem

Every DLP-for-LLM tool — Aegis included, today — replaces a sensitive value with an **opaque
token** and hopes to swap it back later:

- index placeholder: `[[REDACTED:ANTHROPIC_KEY:1]]`  ([`src/scrub/placeholders.ts`](../src/scrub/placeholders.ts))
- ciphertext blob: `[[AEGIS:9f8a…]]`  ([`src/crypto.ts`](../src/crypto.ts))

Both are correct for *privacy* but bad for *utility*, and that tension is the actual open problem:

1. **Utility collapse.** The model can no longer reason about the value. Ask it to "fix the regex
   that validates this email" and it sees `[[REDACTED:EMAIL:1]]` — the shape, length, and class
   of the value are gone, so its answer degrades. This is the well-studied **privacy–utility
   tradeoff** (Dwork & Roth, 2014, §1).
2. **Format breakage.** Generated code that string-interpolates the token produces invalid output
   (`connect("[[REDACTED:IPV4:1]]")` is not a valid host).
3. **Token bloat.** Ciphertext tokens are long; the README already flags this as the reason
   encryption mode is not the default.
4. **Brittle round-trip.** Restoration ([`src/stream.ts`](../src/stream.ts),
   [`Vault.restore`](../src/scrub/placeholders.ts)) is **exact string match**. If the model
   reformats, re-cases, line-wraps, or paraphrases the token, restoration silently fails and the
   user gets a broken answer with a dangling placeholder.

No shipping tool in this category solves 1–4 together. That is the gap these three contributions
target.

| # | Contribution | Class | Basis |
|---|---|---|---|
| **C1** | **SFT** — Semantic Format-Preserving Tokenization | flagship | NIST SP 800-38G FF3-1 (FPE) + a novel *referential-integrity* layer |
| **C2** | **DTR** — Drift-Tolerant Restoration | new algorithm | SimHash LSH (Charikar 2002) + bounded edit distance |
| **C3** | **DP-Fleet** — Differentially-private telemetry | applied research | Laplace mechanism (Dwork et al. 2006) |

Everything below preserves Aegis's invariants: **no network for detection, no API key, real
values never leave the machine, audit records counts only.**

---

## C1 — Semantic Format-Preserving Tokenization (SFT)

### Idea

Replace each sensitive value with a **different value of the same type and format** — a fake API
key that still looks like an API key, a fake-but-valid IPv4, a Luhn-valid fake card, a
plausible fake name — deterministically and reversibly, with a **local key**. The model reasons
correctly because the surrogate has the right shape; the response is mapped back on the way out.

```
real:      sk-ant-api03-9Q…kZ     alice@acme.com     10.2.14.7      Project Phoenix
surrogate: sk-ant-api03-2Fx…7b     wpjlq@acme-corp.io 188.44.201.9   Project Zenith
                    ^ same prefix/charset/length      ^ valid quad    ^ consistent codename
```

### C1a — Format-Preserving Encryption core (FF3-1)

We implement **FF3-1** from **NIST SP 800-38G** (Dworkin, 2016; 2019 revision that shortens the
tweak to 56 bits to resolve the Durak–Vaudenay / Hoang–Miller–Trieu attack on FF3). FF3-1 is a
Feistel network whose round function is AES (available in Node `crypto`, no new dependency):

- Encrypts a numeral string of radix `r`, length `n`, into another numeral string of the **same
  radix and length** — i.e. it's a keyed permutation of the domain `Z_(r^n)`.
- 8 Feistel rounds; each round AES-encrypts a block derived from the 56-bit tweak, the round
  index, and one half interpreted as an integer, then adds (mod `r^(n/2)`) into the other half.
- Deterministic and invertible with the same key + tweak. We use `dec = FF3.decrypt(key, tweak, ·)`
  for restoration.
- Big values exceed 2^53, so half-values are handled with `BigInt`.

**Per-type format specs** (a small registry, one entry per detector `type`):

| type | domain handed to FPE | preserved invariants |
|---|---|---|
| `ANTHROPIC_KEY`, `OPENAI_KEY`, `GITHUB_TOKEN`, … | body after the literal prefix, over base62 | prefix, length, charset |
| `EMAIL` | local-part over `[a-z0-9]`; domain → stable surrogate domain | `@`, dot structure, length |
| `IPV4` | the 32-bit integer, radix 2^16 × len 2 | dotted-quad, each octet ≤ 255 |
| `CREDIT_CARD` | first `n−1` digits via FPE, **recompute Luhn check digit** | length, Luhn-valid |
| `PHONE`, `SSN` | digit domain (radix 10) | length, digit grouping |
| generic `secret=` / high-entropy | base62 over the value body | length, charset |

The **tweak** is derived per value from `type` (domain separation, so an email can't map onto a
key's codomain). The **key** is a new 256-bit local key at `~/.aegis/fpe.key` (mode `0600`),
generated on first use exactly like the existing `redaction.key`
([`loadOrCreateKey`](../src/crypto.ts)).

**Small-domain safety.** FPE is weak when `r^n` is tiny (a 3-digit value has only 1000
possibilities). Per SP 800-38G guidance we set a minimum-domain threshold
(`r^n ≥ 1,000,000`); values below it (e.g. a short SSN fragment) fall back to a **keyed-hash
pseudonym** drawn from the correct alphabet (HMAC-SHA-256(key, type‖value) → base-r digits).
Reversibility for that fallback is preserved by a per-request vault entry, exactly as today.

### C1b — Referential integrity (the novel layer)

Deterministic tokenization already gives *identical-value* consistency (same input → same output;
Aegis's `forward` map does this). The **new** contribution is **co-reference preservation across
related-but-not-identical values**, so the model's reasoning graph survives redaction:

```
Project Phoenix  ─┐                    Project Zenith  ─┐
phoenix-db        ─┼─ share stem       zenith-db        ─┼─ share surrogate stem
phoenix@acme.com  ─┘  "phoenix"        zenith@…         ─┘  "zenith"
```

**Algorithm (StemRegistry):**

1. **Stem extraction.** For a matched value, extract normalized stems: lowercase, split on
   non-alphanumerics, drop stems shorter than 3 chars and a small stoplist. `phoenix-db` →
   `{phoenix, db}`; `Project Phoenix` → `{project, phoenix}`.
2. **Stem surrogate.** Each real stem maps to a surrogate stem via a **keyed deterministic draw**
   from a bundled neutral wordlist: `idx = HMAC(key, "stem"‖stem) mod |wordlist|`. This is stable
   across requests and machines sharing the key (`phoenix → zenith` always).
3. **Compose.** The value's surrogate is built by substituting each real stem's characters with
   its surrogate stem while preserving delimiters, case pattern, and any structured remainder
   (which still goes through FPE). Non-stem structure (the `@acme.com`, the `-db`) is handled by
   the type's format spec so the whole surrogate stays well-formed.
4. **Restore.** The reverse maps surrogate value → real value. Exact surrogates are kept in the
   per-request vault (fast path); the keyed stem map also lets DTR (C2) recover drifted forms.

This is what lets an agent refactor `phoenix-db` and `PhoenixClient` coherently and get back
real names in the right places — something opaque placeholders and per-value ciphertext cannot do.

### Integration

- New module `src/scrub/fpe.ts` (FF3-1 primitive) + `src/scrub/tokenizer.ts` (format registry,
  StemRegistry, `Tokenizer` implementing `tokenFor(value,type)` / `detokenize(text)`).
- `Vault` ([`placeholders.ts`](../src/scrub/placeholders.ts)) gains a third strategy. Selection
  via a unified config field:

  ```jsonc
  "tokenization": {
    "mode": "fpt",              // "placeholder" (default) | "encrypt" | "fpt"
    "referentialIntegrity": true
  }
  ```

  Back-compat: existing `encryption.enabled: true` continues to mean `mode: "encrypt"`.
- `Scrubber.replace` ([`scrub/index.ts`](../src/scrub/index.ts)) is unchanged — it already calls
  `vault.placeholderFor(value, type)`; the Vault decides the strategy.
- `stream.ts` restorer: the exact-match fast path is unchanged; DTR (C2) is layered after it.

### Security analysis

- **Confidentiality:** FF3-1 is a NIST-approved PRP; without the local key the surrogate is
  computationally unlinkable to the plaintext, subject to the documented small-domain caveat
  (handled by the fallback).
- **Key handling:** identical to the existing encryption key — local, `0600`, never transmitted.
- **Fail-closed restore:** an un-mappable surrogate is left as-is (never guessed), same posture as
  `decrypt(...) ?? m` today.
- **New risk — plausibility:** because surrogates look real, a user glancing at *upstream* traffic
  could mistake a surrogate for a real secret. Mitigation: surrogates are only ever sent upstream
  (by design), never surfaced to the user; audit still logs counts/types only.

### Honest limitations

- FPE only truly "preserves format" for values we have a format spec for; unknown structures fall
  back to charset-preserving encryption (still reversible, still same length/charset, but not
  semantically typed).
- Referential integrity is stem-based heuristic co-reference, not semantic understanding; it links
  `phoenix-db`↔`Project Phoenix`, but won't link a codename to an unrelated internal synonym.
- Longer than an index placeholder (though far shorter than the AES-GCM blob), so it costs some
  tokens; it is opt-in.

---

## C2 — Drift-Tolerant Restoration (DTR)

### Problem

Restoration today is exact string match. Models routinely **mutate** echoed tokens: change case,
insert a space/newline in the middle of a long key, wrap a line, add markdown backticks, or
paraphrase. Any mutation → the token no longer matches → the user gets a dangling surrogate and a
broken answer. FPE surrogates (C1) reduce this (they look like values to keep verbatim) but do not
eliminate it. **No LLM-DLP tool handles token drift.**

### Algorithm

A two-stage recover-after-exact-miss pass, run only over text the exact restorer left behind.

**Index build (once per request, over minted surrogates):**
- For each surrogate `s`, compute `SimHash64(s)` over character 4-grams (Charikar, 2002): hash each
  shingle to 64 bits, sum signed bit-votes, take the sign per bit → a 64-bit signature where
  Hamming distance approximates cosine similarity of shingle sets.
- Insert into an **LSH band index**: split the 64-bit signature into `b=8` bands of `r=8` bits;
  index each band value → surrogate. Near-duplicates collide in ≥1 band with high probability
  (Indyk–Motwani, 1998; Leskovec–Rajaraman–Ullman, *MMDS*, ch. 3).

**Recovery (over residual response text):**
1. **Candidate extraction.** Tokenize residual text into candidate spans that *could* be a drifted
   surrogate: contiguous high-entropy runs, email-shaped, key-prefix-shaped, dotted-quad-shaped —
   cheap regex, reusing detector shapes.
2. **LSH query.** For each candidate compute `SimHash64` and look up its bands; gather surrogate
   candidates sharing ≥1 band.
3. **Verify (fail-closed gate).** Accept a match only if **both**:
   - Hamming distance ≤ `maxHamming` (default 6 of 64), and
   - normalized Levenshtein distance ≤ `maxEditRatio` (default 0.15) — bounded DP edit distance
     (Wagner–Fischer) with early exit.
   Only on acceptance do we substitute the real value. Ambiguous (two surrogates tie) → skip.
4. **Audit.** Emit a `drift` event (counts only: how many tokens were drift-recovered) so the
   effect is measurable.

Complexity: index `O(m)` in surrogate count; recovery `O(c · candidates_per_band)`, both tiny for
realistic message sizes.

### Why it's safe (false-restore analysis)

The match set is **closed**: candidates are only ever matched against surrogates *we minted this
request*. Surrogates are high-entropy and unique, so the probability that unrelated model-generated
text lands within Hamming 6 **and** edit-ratio 0.15 of a specific minted surrogate is negligible.
The double gate (LSH similarity **and** exact-ish edit distance) plus fail-closed-on-tie makes a
wrong restoration far less likely than the broken-output status quo it replaces.

### Integration

- New module `src/scrub/dtr.ts`: `SimHash`, `LshIndex`, `boundedLevenshtein`, `DriftRestorer`.
- `Vault` exposes its surrogate set to build the index; `Vault.restore` gets an optional
  drift-tolerant second pass; `SseRestorer.flushCarry`/`end` run DTR on the fully-assembled tail
  (drift recovery needs a complete token, so it runs at flush points, not per-delta).
- Config:

  ```jsonc
  "restore": { "driftTolerant": { "enabled": true, "maxHamming": 6, "maxEditRatio": 0.15 } }
  ```

### Honest limitations

- Runs at flush boundaries, not mid-delta, so a drift-recovered token appears slightly later in a
  stream than an exact one (correctness over latency).
- Tuned to prefer *misses over wrong restores*; a badly-mangled token may still be left as the
  surrogate rather than risk a false swap.
- Adds CPU vs. pure exact match (bounded, opt-in).

---

## C3 — Differentially-Private fleet telemetry (DP-Fleet)

### Problem

The fleet collector ([`src/fleet.ts`](../src/fleet.ts)) aggregates and exposes **exact** per-user
and total spend at `GET /fleet/summary`. Anyone with viewer access to that endpoint learns exactly
how much any individual engineer used — a privacy leak inside a privacy tool.

### Algorithm

Apply the **Laplace mechanism** (Dwork, McSherry, Nissim, Smith, 2006) to the *released aggregate*
statistics, giving ε-differential privacy for org-level numbers:

1. **Clamp** each contributing unit to a configured cap `C` (tokens) / `C$` (cost). Clamping bounds
   the **sensitivity** `Δf = C` of a sum query (one unit can change the sum by at most `C`).
2. **Add noise** `Lap(0, Δf/ε)` to each released aggregate (org totals; optionally per-user
   cross-host sums). Sampling uses `crypto.randomBytes` → uniform `u∈(0,1)` → inverse CDF
   `−(Δf/ε)·sgn(u−½)·ln(1−2|u−½|)` (cryptographically-seeded, not `Math.random`).
3. **Split the budget** ε across the number of released statistics (sequential composition, Dwork &
   Roth 2014, Thm 3.16) so the total guarantee is the configured ε.
4. **Post-process:** clamp noised values to ≥0 and round (post-processing invariance keeps DP).

The **exact** per-host store is unchanged for the *admin* path; DP is applied at the summary
release boundary via a new `summaryPrivate(epsilon)` and an opt-in flag, so a viewer sees useful
totals without learning any individual's exact spend.

### Integration

- `FleetAggregator` gains `summaryPrivate(cfg)` alongside `summary()`. `startFleetCollector` serves
  the DP summary when privacy is enabled and the caller's role is below admin
  (ties into existing [`src/auth.ts`](../src/auth.ts) RBAC).
- Config:

  ```jsonc
  "fleet": {
    "privacy": { "enabled": true, "epsilon": 1.0, "clampTokens": 500000, "clampCostUsd": 50 }
  }
  ```

### Honest limitations

- DP protects the **released aggregate**, not the raw reports the collector must store to dedup per
  host; the guarantee is for what viewers can query, not for a DB compromise.
- Small ε (strong privacy) adds visible noise to totals; this is the fundamental DP tradeoff, made
  explicit and tunable.
- It is ε-DP for a single release; repeated queries compose (documented), so the endpoint returns a
  cached noised release per window rather than re-sampling per call.

---

## Evaluation plan (how we prove each claim)

New tests, added to the existing Vitest suite:

- **`test/fpe.test.ts`** — FF3-1 round-trips over multiple radices/lengths; matches NIST SP 800-38G
  sample vectors; permutation property (distinct inputs → distinct outputs); tweak domain
  separation.
- **`test/tokenizer.test.ts`** — every format spec yields a **same-format, type-valid** surrogate
  (email is email-shaped, IPv4 octets ≤255, card passes Luhn); full redact→restore round-trip;
  **referential integrity** (related inputs share surrogate stems; unrelated don't collide).
- **`test/dtr.test.ts`** — deliberately corrupt surrogates (case flip, injected space/newline,
  markdown wrap, truncation) and assert DTR restores them; assert it **refuses** to restore random
  high-entropy text (no false restores); Hamming/edit-ratio boundary behavior.
- **`test/dp.test.ts`** — noised totals are within a statistical band of the true totals; clamping
  bounds sensitivity; noise scale tracks ε; determinism of the per-window cached release.
- **Benchmark extension** — add drift + format cases to [`src/benchmark.ts`](../src/benchmark.ts)
  so the CI gate ([`test/benchmark.test.ts`](../test/benchmark.test.ts)) also protects
  restore-recall.
- **README + this whitepaper** updated; claims phrased as *measured on the corpus*, not absolutes.

---

## References

1. Dworkin, M. **Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving
   Encryption.** NIST Special Publication 800-38G, 2016 (and the 2019 revision defining FF3-1).
2. Bellare, M., Rogaway, P., Spies, T. **The FFX Mode of Operation for Format-Preserving
   Encryption.** 2010.
3. Durak, F. B., Vaudenay, S. **Breaking the FF3 Format-Preserving Encryption Standard over Small
   Domains.** CRYPTO 2017. (Motivates FF3-1's 56-bit tweak.)
4. Charikar, M. **Similarity Estimation Techniques from Rounding Algorithms.** STOC 2002. (SimHash.)
5. Indyk, P., Motwani, R. **Approximate Nearest Neighbors: Towards Removing the Curse of
   Dimensionality.** STOC 1998. (LSH.)
6. Leskovec, J., Rajaraman, A., Ullman, J. **Mining of Massive Datasets**, ch. 3 (LSH banding).
7. Wagner, R. A., Fischer, M. J. **The String-to-String Correction Problem.** JACM 1974.
   (Edit distance.)
8. Dwork, C., McSherry, F., Nissim, K., Smith, A. **Calibrating Noise to Sensitivity in Private
   Data Analysis.** TCC 2006. (Laplace mechanism.)
9. Dwork, C., Roth, A. **The Algorithmic Foundations of Differential Privacy.** 2014.
   (Composition, post-processing.)

---

## Deliverables checklist (on approval)

- [ ] `src/scrub/fpe.ts` — FF3-1 primitive (+ vectors test)
- [ ] `src/scrub/tokenizer.ts` — format registry + StemRegistry + Tokenizer
- [ ] `Vault` third strategy `mode: "fpt"` + config plumbing in [`config.ts`](../src/config.ts) / [`types.ts`](../src/types.ts)
- [ ] `src/scrub/dtr.ts` — SimHash + LSH + bounded edit distance + `DriftRestorer`
- [ ] DTR pass wired into `Vault.restore` / `SseRestorer`
- [ ] `FleetAggregator.summaryPrivate` + Laplace sampler + collector wiring
- [ ] 4 new test files + benchmark corpus extension
- [ ] README section + config example updates
