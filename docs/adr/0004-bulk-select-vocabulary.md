# ADR 0004: Bulk selection vocabulary (supersedes ADR 0002 and ADR 0003)

## Status

Accepted (2026-06-27)

Supersedes [ADR 0002](0002-inject-attribute-pregate-opt-in.md) and
[ADR 0003](0003-rename-inject-bulk-attributes.md). Behavior decided in those
ADRs is retained; **names** are corrected so store policy, selection gates, and
exec inject supply use separate vocabulary.

## Context

Design §13 #2 asked whether store attributes should filter `exec` secret supply
by default or only when a gate is enabled. [ADR 0002](0002-inject-attribute-pregate-opt-in.md)
answered **opt-in**: attributes apply only when a bulk gate flag is present.

[ADR 0003](0003-rename-inject-bulk-attributes.md) renamed `sandbox_inject` and
related CLI flags toward bulk-scoped language but kept **`inject` on store
attributes and listing/export flags** (`inject_bulk`, `--inject-bulk-gate`).
That conflates two concepts:

| Layer | Meaning | Example |
| --- | --- | --- |
| **Bulk selection policy** | Whether a key may participate when bulk selection runs with the gate enabled | `export --pattern … --bulk-gate` |
| **Exec inject supply** | How chosen ambient/store values are mapped into the child environment | `exec --inject secret:only=…` |

`export` does not inject secrets into a child process. Naming export and listing
commands with `inject_*` identifiers was a lineage artifact from
`sandbox_inject` / `--sandbox-injectable`, not an accurate description of the
behavior.

v2 already splits bulk authorization across domain entry and secret object.
Inject pentads (`secret:only`, `secret:reject`, `final:reject`, and related
rules) remain the exec-specific prohibition and shaping layer. Searchable `meta`
(`FIELD=VALUE`) is unchanged.

## Decision

Adopt **operation-neutral bulk selection vocabulary** for store attributes and
gate flags. Reserve **`inject` for exec child-process supply only**
(`--inject`, `--inject-file`, pentad rules).

### Naming principles

1. **`inject` is exec-only** — child environment supply and YAML/JSON inject
   plan observation.
2. **Store attributes are verbs-free policy nouns** — parallel to
   `key_visibility` and `value_access`.
3. **Gate flags are command-uniform** — one flag name across
   `ls`, `list`, `export`, `fuse`, and `exec`.
4. **`exclude` is gate-scoped** — it means “not selectable in bulk selection
   when `--bulk-gate` is active,” not “never leave the store.” Direct named
   paths (`get`, gateless `export --pattern`, gateless `exec --inject
   secret:only=…`) remain outside this attribute family.
5. **Legacy names are rejected with hints** — not accepted as silent aliases.
   Disk readers accept old field names and token values during transition;
   rewrites emit canonical names only.

### Vocabulary

#### Store attributes

| Layer | Canonical name | Tokens | Meaning |
| --- | --- | --- | --- |
| Effective attribute (`attr`, `ls --json`, SDK) | `bulk_select` | `exclude`, `named`, `include` | Combined bulk-selection eligibility shown to users |
| v2 domain entry field | `bulk_select_entry` | `exclude`, `named`, `include` | Link/name side of bulk policy |
| v2 secret object field | `bulk_select_value` | `exclude`, `include` | Value/object side of bulk policy |

`named` remains reserved for a future explicit-key bulk flow and is excluded
by the current `--bulk-gate` policy gate.

A bulk-gated selection is permitted only when both v2 legs allow it.

#### CLI flags

| Role | Canonical flag | Commands |
| --- | --- | --- |
| Enable bulk-selection attribute pre-filter | `--bulk-gate` | `ls`, `list`, `export`, `fuse`, `exec` |
| Set bulk selection policy on a key | `--bulk-select MODE` | `attr`, `set` |
| Exec child supply rules | `--inject LAYER:KIND=…` | `exec` only |
| Exec policy file | `--inject-file FILE` | `exec` only |

**Remove** `--inject-gate` from the supported CLI surface. YAML/JSON exec
policies use `bulk_gate: true` (boolean) instead of `gate: bulk` or
`gate: sandbox`.

#### JSON / SDK observation fields

| Field | Meaning |
| --- | --- |
| `bulk_select` | Effective attribute on keys |
| `bulk_gate` | Whether the command applied the bulk gate (boolean) |
| Pentad / plan fields | Unchanged inject vocabulary where describing exec supply |

Rename migration counters such as `injectable_entries` to `bulk_select_entries`.

### Selection modes (behavior — unchanged from ADR 0002)

**Direct visible-key selection** — no bulk gate:

- `export --pattern GLOB`
- `get KEYREF`
- gateless `exec --inject secret:only=…` (and analogous pentad selectors)

**Bulk selection with attribute pre-filter** — `--bulk-gate` present (or a
future domain default):

- `ls` / `list` / `export` / `fuse` with pattern or profile filters plus
  `--bulk-gate`
- `exec` with pentad selectors plus `--bulk-gate`

Do **not** apply `bulk_select_value=exclude` (or entry-side restrictions) to
exec alone while leaving direct `export --pattern` unfiltered. Cross-command
consistency is required.

Key-level prohibitions inside exec use pentad rules (`secret:reject`,
`final:reject`), not attribute reinterpretation.

### Legacy rejection and on-disk compatibility

#### CLI and token rejection hints

| Rejected input | Hint |
| --- | --- |
| `--sandbox-inject`, `--sandbox-injectable` | Phase 3 / pre-0003 legacy |
| `--inject-bulk`, `--inject-bulk-gate` | ADR 0003 names → `--bulk-select`, `--bulk-gate` |
| `--inject-gate=bulk`, `--inject-gate=sandbox` | → `--bulk-gate` |
| `gate: bulk`, `gate: sandbox` in YAML | → `bulk_gate: true` |
| Tokens `never`, `explicit`, `bulk`, `allow` on CLI | → `exclude`, `named`, `include` |

#### On-disk read compat (transition period)

Readers accept legacy v1/v2 field names and token values; writers emit canonical
names only:

| Read alias | Canonical write |
| --- | --- |
| `sandbox_inject`, `inject_bulk` | `bulk_select` |
| `entry_inject`, `inject_bulk_entry` | `bulk_select_entry` |
| `secret_inject`, `inject_bulk_value` | `bulk_select_value` |
| `never` / `explicit` / `bulk` / `allow` | `exclude` / `named` / `include` |

### Internal identifiers

Rename C/SDK/bindings internal symbols to match user-facing vocabulary
(`secdat_bulk_select`, `bulk_gate`, `bulk_select_entry`, etc.) in the same
change set as the CLI cutover to avoid a second rename pass.

## Consequences

### Positive

- Store policy reads as **selection rules**, not inject/export verbs.
- `export --bulk-gate` and `exec --bulk-gate` describe the same gate; inject
  wording is confined to exec supply.
- ADR 0002 behavior and ADR 0003 token semantics (`exclude` / `named` /
  `include`) are preserved without carrying `inject_bulk` naming debt.

### Negative

- Another breaking rename on top of ADR 0003 (`inject_bulk` had a short life).
- Broader doc/test/binding churn; ADR 0003 strings become additional legacy
  rejection targets.
- Operators mid-migration must follow the rejection hints twice if they already
  adopted ADR 0003 names.

### Non-goals

- Domain defaults that enable `--bulk-gate` without an explicit flag (future ADR).
- A separate absolute egress attribute; use pentad rules or a future ADR.
- Changing [ADR 0001](0001-inject-file-yaml-only.md) YAML-only policy files or
  pentad grammar.

## Implementation notes

- Update `docs/secdat-spec.md` FR-3ab, `README.md`, man pages, `po/ja.po`,
  `docs/exec-injection-design.md`, bindings, and regression tests.
- Close design §13 #2 under this ADR.
- Regression tests must cover rejection of ADR 0003 CLI names with hints toward
  ADR 0004 names.

## References

- [ADR 0001](0001-inject-file-yaml-only.md)
- [ADR 0002](0002-inject-attribute-pregate-opt-in.md) (superseded)
- [ADR 0003](0003-rename-inject-bulk-attributes.md) (superseded)
- `docs/exec-injection-design.md` §10, §13
- `docs/secdat-spec.md` FR-3ab, v2 store layout
- `src/store.c`, `src/cli.c`, `src/exec_inject.c`, `src/secdat-fuse.c`