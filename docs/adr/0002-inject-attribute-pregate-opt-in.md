# ADR 0002: exec attribute pre-gate is opt-in via `--inject-gate=sandbox`

## Status

Accepted (2026-06-27)

## Context

Design §13 #2 asked whether store attributes such as `secret_inject=never` and
effective `sandbox_inject` should filter `exec` secret supply by default or only
when a gate is enabled.

The project already distinguishes two selection modes across commands:

- **Direct visible-key selection** — pattern or named selectors without a bulk
  gate (`export --pattern`, `get KEYREF`, and analogous paths).
- **Scoped sandbox / bulk selection** — attribute-aware filtering when
  `--sandbox-injectable` (or the exec replacement `--inject-gate=sandbox`) is
  present.

`docs/secdat-spec.md` documents this for export and listing. v2 splits injection
authorization into `entry_inject` on the domain entry and `secret_inject` on the
secret object; the CLI bulk gate uses the combined effective `sandbox_inject`
attribute.

Inject pentads (`secret:only`, `secret:reject`, and related rules) live outside
store attributes (design §10). Searchable `meta` data (`FIELD=VALUE`) is unrelated
to injection supply and must not be conflated with `attr` policy fields.

## Decision

Store attribute pre-filtering for `exec` secret supply is **opt-in**:

- **Without** `--inject-gate=sandbox` (and without an equivalent future domain
  default): visible keys remain candidates; pentad rules choose among them. This
  mirrors `export --pattern` without `--sandbox-injectable`.
- **With** `--inject-gate=sandbox` (or YAML `gate: sandbox`): apply the same
  effective `sandbox_inject` bulk filter used by `export --sandbox-injectable`,
  `ls --sandbox-injectable`, and related commands.

Do **not** apply `secret_inject=never` or other attribute checks to exec alone
while leaving direct `export --pattern` unfiltered. That would break cross-command
consistency.

Key-level prohibitions in inject policy use pentad rules (`secret:reject`,
`final:reject`), not attribute reinterpretation.

This ADR does **not** change `attr`, `meta`, or relation semantics. It records
how existing attribute meaning maps onto exec:

| Attribute / field | Meaning (unchanged) | exec effect |
| --- | --- | --- |
| `attr` / `sandbox_inject` | Scoped sandbox inject/export eligibility | Honored only when `--inject-gate=sandbox` |
| v2 `secret_inject` | Object-level allow/never merged into effective inject policy | Same as above via effective `sandbox_inject` |
| `meta` | Non-secret searchable labels | No inject supply effect |

## Consequences

### Positive

- Preserves export / ls / fuse / exec symmetry for direct vs bulk selection.
- Keeps pentad vocabulary as the inject-specific prohibition layer.
- Matches spec FR-3ab wording that `sandbox_inject=never` excludes keys from
  **sandbox injection/export selection**, not from all operator-named access paths.
- Leaves room for future **domain defaults** that enable the sandbox gate without
  redefining attribute semantics.

### Negative

- Operators who want attribute-scoped exec must pass `--inject-gate=sandbox` (or
  set a future domain default). This is explicit, not automatic.
- `secret:only=KEY` can still inject a visible key whose effective
  `sandbox_inject` is not `bulk`; operators must combine the sandbox gate when
  they intend attribute-scoped bulk behavior.

### Follow-up

- Close design §13 #2 and reference this ADR.
- Update stale user docs that still mention `exec --sandbox-injectable` (PR-8).

## Related decisions

- [ADR 0003](0003-rename-inject-bulk-attributes.md) renames attributes and CLI
  flags so bulk-scoped behavior is not implied by `never` / `sandbox_inject`
  vocabulary. Behavior in this ADR is unchanged.

## References

- [ADR 0001](0001-inject-file-yaml-only.md)
- `docs/exec-injection-design.md` §10, §13
- `docs/secdat-spec.md` FR-3ab, v2 `entry_inject` / `secret_inject`
- `src/exec_inject.c` (`--inject-gate=sandbox`)
- `src/store.c` (`secdat_sandbox_inject_allows_bulk_selection`)