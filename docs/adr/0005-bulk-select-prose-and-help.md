# ADR 0005: Bulk selection prose, help, and error-message polish

## Status

Accepted (2026-06-27)

Follows [ADR 0004](0004-bulk-select-vocabulary.md). **No identifier rename**;
this ADR fixes user-facing **wording** left inconsistent after the ADR 0004
cutover.

## Context

[ADR 0004](0004-bulk-select-vocabulary.md) separated identifiers:

- **Selection policy** — `bulk_select`, `--bulk-select`, `--bulk-gate`, `bulk_gate`
- **Exec supply** — `--inject`, `--inject-file`, pentad rules

Post-implementation review found remaining unnatural language:

1. **Category confusion** — `list` help describes `--bulk-gate` as a “local
   state” like `masked` or `orphaned`, but the flag is a **selection filter**,
   not a tombstone/storage category.
2. **Prose regression** — spec and man pages still say “bulk-gated
   inject/export/list selection” and “exec injects only keys…”, reintroducing
   `inject` into export/list explanations.
3. **Redundant wording** — help says “`bulk_select` bulk pre-filter” (`bulk`
   twice).
4. **Documentation damage** — automated edits left strings such as
   `` `--bulk-gate (legacy `--inject-gate` rejected)` `` inside normative spec
   bullets.
5. **Man synopsis drift** — `docs/secdat.1` exec synopsis still shows
   `--inject-gate GATE` while the body documents `--bulk-gate`.
6. **Misleading rejection hints** — `attr`/`set` reject mistaken `--inject` with
   only “use `--bulk-select`”, which does not steer exec users back to pentads.
7. **Opaque token** — `bulk_select=named` is reserved/future but reads like a
   typo without a glossary entry.

Identifiers from ADR 0004 (`bulk_select`, `--bulk-select`, `--bulk-gate`,
`named`, `exclude`, `include`) are **retained**. Another breaking rename is out
of scope.

## Decision

### Canonical user-facing vocabulary

Use these phrases in help, spec prose, man pages, `po/ja.po`, and design docs.
**Do not** use them as CLI or JSON field names unless already canonical.

| Concept | Canonical prose (English) | Avoid in prose |
| --- | --- | --- |
| Cross-command filter | **bulk-gated selection** | “sandbox inject”, “inject/export/list selection” as a bundle |
| Store attribute | **`bulk_select` policy** (or “bulk selection policy”) | “inject policy”, “inject attribute” |
| Gate flag | **`--bulk-gate`** enables the attribute pre-filter | “inject gate”, “sandbox-injectable” |
| attr/set flag | **`--bulk-select`** sets `bulk_select` on a key | implying the flag performs selection |
| Exec-only | **secret supply** / **child environment** | saying `export` or `ls` “injects” |
| exec + gate | “`--bulk-gate` applies the `bulk_select` pre-filter before secret supply” | “exec injects only keys…” as the primary gate description |

**Rule:** `inject` appears in user-facing text only when describing **exec pentad
supply** (`--inject`, plan JSON supply/route/final, child env). Listing and
export commands **select** or **emit** keys; they do not inject.

### Token glossary (`bulk_select` / `bulk_select_entry`)

| Token | Meaning |
| --- | --- |
| `exclude` | Not eligible when `--bulk-gate` is active (not “never leave the store”) |
| `include` | Eligible for bulk-gated selection when the gate is active |
| `named` | **Reserved** for a future explicit-key bulk path; **excluded** by the current `--bulk-gate` filter. Legacy disk/CLI token `explicit` maps to `named` on read. |

Document `named` once in FR-3ab and attr help; do not rename the token again.

### Help and CLI detail strings

Replace misleading lines as follows:

| Location | Current (wrong) | Replace with |
| --- | --- | --- |
| `list` / global list detail | “…or bulk-gate **local state**” | “…or filter local entries with **`--bulk-gate`** (bulk selection policy)” |
| `attr` detail | “bulk-select **attributes**” (plural) | “**`bulk_select` attribute**” |
| `exec` detail | “`bulk_select` **bulk** pre-filter” | “**`bulk_select` pre-filter**” |
| `attr` detail (eligibility) | “bulk-gated export/exec eligibility” | “eligibility for **bulk-gated selection** on export, list, and exec” |

`ls --bulk-gate` and `export --bulk-gate` help MUST NOT mention secret supply or
injection.

### Legacy rejection text

Legacy hints stay **short and separate** from normative option descriptions.

- Normative bullets name only canonical flags: `--bulk-gate`, `--bulk-select`.
- A dedicated “Legacy rejection” bullet lists removed flags
  (`--sandbox-inject*`, `--inject-bulk*`, `--inject-gate`, YAML `gate:`) and
  states they fail with a replacement hint.
- **Never** embed legacy parentheticals inside canonical flag names (e.g. forbid
  `` `--bulk-gate (legacy …)` `` in spec prose).

### `attr` / `set` mistaken `--inject` hint

When `--inject` is passed to `attr` or `set`, reject with a **two-part** hint:

```
--inject is not valid for attr; use --bulk-select to set bulk_select policy (exec supply rules use --inject on exec)
```

(`set` uses “not valid for set” in the same pattern.)

Do not imply `--inject` is an alias for `--bulk-select`.

### Man pages and design docs

- `docs/secdat.1` exec **synopsis** MUST match ADR 0004: `[--bulk-gate]`, not
  `[--inject-gate GATE]`.
- `docs/secdat-spec.md` FR-3ab and §4.8a: replace “inject/export/list” bundles
  with “bulk-gated selection”; exec bullet describes **secret supply** after the
  pre-filter.
- `docs/exec-injection-design.md`: align §7–§15 with ADR 0004/0005 vocabulary;
  remove `sandbox_inject` except in migration tables; fix corrupted
  parenthetical strings.
- `docs/secdat-fuse.1`: legacy rejection note only; canonical flag `--bulk-gate`.

### JSON / observation fields (unchanged)

Per ADR 0004: `bulk_select` on keys, `bulk_gate` boolean on command plans.
Prose in JSON schema descriptions follows the canonical vocabulary above.

### Internal C identifiers (non-goals)

Renaming `secdat_bulk_select_allows_bulk_selection` or similar internal
symbols is optional cleanup, not required for this ADR.

## Consequences

### Positive

- Help text matches the ADR 0004 mental model (filter vs local state; selection
  vs inject).
- Spec and man pages become safe to cite without teaching the wrong verb per
  command.
- `named` is documented without another token rename.
- Legacy migration story stays in rejection/migration sections only.

### Negative

- Touches many doc/help/`po` strings; no functional change, but wide diff.
- Japanese translations must be updated for revised help lines.

### Non-goals

- Renaming `named`, `--bulk-select`, or `bulk_select`.
- Changing bulk-gate opt-in behavior (ADR 0002/0004).
- Domain-default `--bulk-gate` (future ADR).

## Implementation checklist

1. `src/cli.c` — help/detail strings per table above.
2. `src/store.c` — `attr`/`set` `--inject` rejection message.
3. `docs/secdat-spec.md` — FR-3ab prose; remove corrupted parentheticals.
4. `docs/secdat.1`, `docs/secdat-fuse.1` — synopsis and prose.
5. `docs/exec-injection-design.md` — vocabulary alignment.
6. `README.md` — same prose rules.
7. `po/ja.po` — msgmerge + translate revised strings.
8. Regression tests that assert help substrings (`session_regression.sh`,
   `export_regression.sh`) if help text changes.

## References

- [ADR 0004](0004-bulk-select-vocabulary.md)
- `docs/secdat-spec.md` FR-3ab, §4.8a
- `src/cli.c`, `src/store.c`
- Post-0004 naming review (conversation, 2026-06-27)