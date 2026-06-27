# ADR 0001: `--inject-file` uses YAML only

## Status

Accepted (2026-06-27)

## Context

`secdat exec` accepts injection policy through repeated `--inject LAYER:KIND=SELECTOR`
tokens and optional `--inject-file FILE` bulk policies. Design §7.4 documents an
`exec.env.yaml` schema. Open question §13 #1 asked whether policy files should also
accept JSON.

The project already uses JSON for machine-readable **observation** (`--json`,
`--json-summary`, `status --json`, and similar). Store metadata and other
human-edited configuration use CLI flags or simple text (`FIELD=VALUE`), not JSON
configuration files.

## Decision

`--inject-file` is **YAML only**. JSON is not a supported policy input format.

Roles are fixed as follows:

| Channel | Role |
| --- | --- |
| `--inject …` | Programmatic and small policy authoring |
| `--inject-file` (YAML) | Large, reviewable, repo-checked static policies |
| `--dry-run --json` / `--json-summary` | Observation and audit of computed plans |

JSON preflight and summary output remain read-only interchange. They are not
round-trip policy formats.

If JSON policy input is reconsidered later, it must map to the same internal IR as
YAML and `--inject` before any parser work begins.

## Consequences

### Positive

- One file-format schema to document, test, and evolve with the pentad IR.
- Preserves the project-wide convention that JSON means observation, not config.
- Avoids maintaining equivalent YAML and JSON policy schemas in parallel.
- Keeps `secret:rename` sed expressions easier to author in YAML than in JSON.

### Negative

- JSON-native CI generators must emit `--inject` arguments or YAML, not JSON policy
  files.
- There is no file-based round trip from `--dry-run --json` output back into policy
  input; that is intentional because output describes computed state, not rules.

### Follow-up

- Close design §13 #1 and reference this ADR.
- Longer term, consider replacing the custom mini YAML parser with a maintained YAML
  library; that is independent of adding JSON input.

## References

- `docs/exec-injection-design.md` §7.4, §8, §13
- `src/exec_inject_policy_file.c`
- `tests/inject_regression.sh`