# ADR 0003: Rename inject attributes to bulk-scoped vocabulary (breaking)

## Status

Accepted (2026-06-27)

## Context

Store inject/export attributes use names that imply absolute authorization
(`sandbox_inject`, `secret_inject`, value `never`) while the implementation
applies them only to **bulk-gated** selection paths (`--inject-gate`,
`--sandbox-injectable`, and analogous listing filters). Direct named selection
(`export --pattern`, gateless `exec --inject secret:only=…`, `get`) intentionally
bypasses these attributes.

This mismatch makes the model feel inconsistent even when behavior is documented.
The exec injection redesign and Phase 3 legacy flag removal already introduce
breaking CLI changes on `feat/inject-regression`; renaming attributes now is
cheaper than carrying misleading names through a stable release.

[ADR 0002](0002-inject-attribute-pregate-opt-in.md) keeps the **opt-in bulk gate**
behavior. This ADR fixes **names** so they describe that behavior honestly.

Searchable `meta` (`FIELD=VALUE`) is unchanged.

## Decision

Adopt a breaking rename so attribute names and enum tokens describe **bulk-gate
eligibility**, not absolute inject/export prohibition.

### Vocabulary

| Layer | Old | New | Meaning |
| --- | --- | --- | --- |
| Effective attribute (ls/json/attr) | `sandbox_inject` | `inject_bulk` | Combined bulk eligibility shown to users |
| v2 domain entry field | `entry_inject` | `inject_bulk_entry` | Link/name side of bulk policy |
| v2 secret object field | `secret_inject` | `inject_bulk_value` | Value/object side of bulk policy |
| Entry/object token | `never` | `exclude` | Excluded when bulk gate is active |
| Entry token | `explicit` | `named` | Reserved for future named-key bulk flows |
| Entry token | `bulk` | `include` | Included in bulk selection when gate is active |
| Object token | `allow` | `include` | Value permitted for bulk selection when entry allows |

`exclude` does **not** mean “never leave the store.” It means “not selectable
through bulk-gated inject/export/list paths.” Operator-named paths remain
outside this attribute family.

### CLI flags

| Old | New |
| --- | --- |
| `attr/set --sandbox-inject` | `--inject-bulk` |
| `ls/list/export/fuse --sandbox-injectable` | `--inject-bulk-gate` |
| `exec --inject-gate=sandbox` | `--inject-gate=bulk` |
| YAML/JSON policy `gate: sandbox` | `gate: bulk` |

Legacy flags removed in Phase 3 (`exec --sandbox-injectable`, etc.) are not
restored under new names on `exec`; `exec` uses `--inject-gate=bulk` only.

### Behavior (unchanged from ADR 0002)

- Bulk attributes filter visible keys **only when** the bulk gate flag is set on
  the command (or a future domain default enables the gate).
- Gateless `exec` pentads and gateless `export --pattern` remain direct
  visible-key selectors.
- Inject-specific prohibitions use pentad `secret:reject` / `final:reject`, not
  bulk attributes.

### Storage and migration

- v1 metadata sidecar key `sandbox_inject` reads legacy values and writes
  `inject_bulk` on rewrite; migration accepts old tokens (`never`, `explicit`,
  `bulk`, metadata alias `allow` → `include`) during a transition release.
- v2 domain-entry and secret-object text fields rename to `inject_bulk_entry` /
  `inject_bulk_value`; fsck/migrate accept old field names until finalize.
- JSON output (`ls --json`, SDK metadata) emits `inject_bulk` only after cutover.

### Documentation

- Remove prose claiming `secret_inject` controls whether a value may leave the
  store “at all.” Replace with bulk-gate scoped language consistent with FR-3ab.
- Update `docs/secdat-spec.md`, `README.md`, man pages, `po/ja.po`, and design
  docs to the new vocabulary.

## Consequences

### Positive

- Names match the opt-in bulk gate model; less reliance on disclaimers.
- v2 split (`entry` vs `value`) reads as two legs of one bulk policy, not
  conflicting “sandbox” vs “secret inject” stories.
- Aligns `exec --inject-gate` with listing/export gate naming (`bulk`).

### Negative

- Breaking change across CLI, on-disk metadata, v2 object sidecars, SDK JSON,
  tests, and user scripts.
- Requires migration shims or a documented one-shot upgrade window.
- `named` remains reserved/future; renaming `explicit` clarifies intent but does
  not by itself deliver the feature.

### Non-goals

- This ADR does not make bulk attributes apply without the gate.
- This ADR does not add a separate absolute egress attribute; use pentad rules
  or a future ADR if that is required.

## References

- [ADR 0001](0001-inject-file-yaml-only.md)
- [ADR 0002](0002-inject-attribute-pregate-opt-in.md)
- `docs/secdat-spec.md` FR-3ab, v2 store layout
- `src/store.c`, `src/cli.c`, `src/exec_inject.c`