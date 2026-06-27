# secdat exec Environment Injection Design

Status: draft (v2 redesign; backward compatibility intentionally out of scope)

## 1. Summary

`secdat exec` builds the child process environment through a fixed three-layer
pipeline:

```
ChildEnv = Demand( Route( Supply_ambient , Supply_secret ) )
```

- **Supply** decides what each source may contribute.
- **Route** resolves same-name variables when both sources contribute them.
- **Demand** validates and shapes the merged result before `execvpe`.

All layers share one small contract vocabulary (**Pentad**). The CLI exposes
this through repeated `--inject` options. Secret values are never printed in
preflight output.

## 2. Goals and Non-Goals

### Goals

- Symmetric, predictable contracts across ambient OS env and store secrets.
- Explicit collision handling between ambient and secret contributions.
- Final existence / non-existence guarantees on the child environment.
- Plan-time validation before secret decryption and child launch.
- Machine-readable preflight (`--dry-run --json`).

### Non-Goals (this design)

- Permanent dual documentation or silent shorthand for legacy `exec` selection
  flags. Legacy flags are accepted only during a **deprecated migration window**
  (see §15); they lower to `--inject` internally and are not the canonical
  interface.
- Parent/child naming (domain inheritance keeps `parent domain`; injection uses
  `ambient`).
- Policy for unrelated commands (`export`, `secdat-fuse`) — may follow later.

## 3. Terminology

| Term | Meaning |
| --- | --- |
| **ambient** | Environment variables inherited from the `secdat exec` caller's OS process (`environ`). Not related to domain inheritance or parent domains. |
| **secret** | Secrets from the resolved store view (`VisibleKeys` for `--dir` / `--store`). Selectors use **key** names before routing; routing and later stages use **env** names. |
| **env name** | Shell environment variable identifier (`[A-Za-z_][A-Za-z0-9_]*`). |
| **bundle** | Internal map `env_name → value_bytes` plus provenance metadata. |
| **collision** | Both ambient and secret bundles contain the same `env_name` after supply filtering. |
| **demand** | Architectural name for the final shaping layer. |
| **final** | CLI prefix for demand-layer rules (`final:...`). |

### Naming choices

| Rejected | Chosen | Reason |
| --- | --- | --- |
| `parent` (supply) | `ambient` | Avoid confusion with parent domain / inheritance. |
| `child:` (demand CLI) | `final:` | Not a polar pair of `ambient`; marks pipeline end. |
| `--policy` | `--inject` | Target is clear; avoids ambiguity with store attrs. |
| `--env` | `--inject` | Avoid clash with `set --env ENVNAME`. |
| `mask` (pentad) | `omit` | Avoid clash with `mask KEYREF` (tombstone). |
| `use` (pentad) | `only` | Clear whitelist semantics; less verb-like. |
| `route:default=fail` | `route:prefer=error` | `prefer` reads as collision-only tie-break. |

## 4. Pentad (Shared Contract Vocabulary)

Every layer uses the same five contracts. Only the selector unit differs.

| Contract | CLI kind | Meaning | On violation |
| --- | --- | --- | --- |
| *(implicit) default* | *(no `only`)* | Include all available entries for this layer | — |
| **only** | `only` | Positive filter: matched entries only (if available) | — |
| **omit** | `omit` | Exclude matched entries silently | — |
| **require** | `require` | Matched entries must be included in this layer's result | Error |
| **reject** | `reject` | Matched entries must not be available at check time | Error |

### Default vs only

```
If no `only` selector is configured for a layer:
    mode = default  → start from all available entries
Else:
    mode = only     → start from available ∩ only-matched entries
```

`omit`, `require`, and `reject` apply after the default/only base set is chosen.

### Evaluation order (within one layer)

```
1. reject  — check availability (before omit); fail if forbidden entry exists
2. base    — default (all available) or only (intersection)
3. omit    — subtract from candidate set
4. require — fail if required entry not in candidate set
5. emit    — build bundle / final env from candidate set
```

### Same-name pentad conflicts (plan error)

- `require` and `omit` overlap on the same selector in the same layer.
- `require` and `reject` overlap on the same selector in the same layer.

## 5. Internal Model

### 5.1 Selector

```c
struct secdat_exec_selector {
    char **names;   /* exact match */
    char **globs;   /* fnmatch-compatible patterns */
};
```

### 5.2 Pentad

```c
struct secdat_exec_pentad {
    struct secdat_exec_selector only;
    struct secdat_exec_selector omit;
    struct secdat_exec_selector require;
    struct secdat_exec_selector reject;
};
```

### 5.3 Supply policy

```c
struct secdat_exec_rename_rule {
    /* one sed-style s/// expression; optional /ADDRESS/ prefix */
    char *expression;
};

struct secdat_exec_supply_policy {
    struct secdat_exec_pentad ambient;   /* selectors: env names */
    struct secdat_exec_pentad secret;    /* selectors: key names */
    struct secdat_exec_rename_rule *secret_rename;
};
```

### 5.4 Route policy

```c
enum secdat_exec_route_pick {
    SECDAT_ROUTE_PICK_SECRET,
    SECDAT_ROUTE_PICK_AMBIENT,
    SECDAT_ROUTE_PICK_ERROR,
};

struct secdat_exec_route_rule {
    struct secdat_exec_selector match;   /* env names / globs */
    enum secdat_exec_route_pick pick;
};

struct secdat_exec_route_policy {
    enum secdat_exec_route_pick prefer;  /* global collision tie-break */
    struct secdat_exec_route_rule *rules; /* overrides; first match wins */
};
```

Default: `prefer = SECDAT_ROUTE_PICK_SECRET`.

### 5.5 Demand policy

```c
struct secdat_exec_demand_policy {
    struct secdat_exec_pentad final;     /* selectors: env names */
};
```

### 5.6 Plan and bundles

```c
struct secdat_exec_env_entry {
    char *name;
    unsigned char *value;
    size_t value_len;
    enum secdat_exec_provenance {
        SECDAT_PROV_AMBIENT,
        SECDAT_PROV_SECRET,
        SECDAT_PROV_ROUTED,
    } provenance;
    char *secret_key;   /* non-NULL when provenance involves secret */
};

struct secdat_exec_plan {
    struct secdat_exec_env_entry *ambient_entries;
    struct secdat_exec_env_entry *secret_entries;
    struct secdat_exec_env_entry *merged_entries;
    struct secdat_exec_env_entry *final_entries;
    struct secdat_exec_collision *collisions;
    struct secdat_exec_plan_error *errors;
};
```

## 6. Pipeline

### Phase 0 — Context

1. Resolve domain chain and `VisibleKeys` for `--dir` / `--store`.
2. Snapshot `AmbientAvail` from the current process environment.
3. Parse `--inject`, optional policy file, and optional `--inject-gate` into
   `supply`, `route`, `demand`, and pre-supply gate structures.
4. When `--inject-gate=sandbox` is set, pre-filter `VisibleKeys` to keys whose
   effective `sandbox_inject` allows bulk selection (see §10).

### Phase 1 — Supply

#### Ambient supply

```
AmbientAvail = { name → value | name exists in caller environ }

1. ambient.reject on env names in AmbientAvail → error if present
2. candidates = all keys or only-matched keys
3. subtract ambient.omit
4. ambient.require → error if missing from candidates
5. AmbientBundle = { name → value }
```

#### Secret supply

```
For each key in VisibleKeys:
    env_name = rename(key)   /* default: env_name = key */
    reject if invalid env_name

SecretAvail = { env_name → (key, value) | key ∈ VisibleKeys }
    /* value loaded only when not dry-run; plan uses presence only */

1. secret.reject on keys in VisibleKeys → error if present
2. candidates = all keys or only-matched keys (key or env_name match)
3. subtract secret.omit (key or mapped env_name)
4. secret.require on keys → error if missing
5. SecretBundle = { env_name → value }
```

Rename runs before pentad evaluation. Two keys mapping to the same `env_name`
→ plan error.

### Phase 2 — Route

For each `name` in `keys(AmbientBundle) ∪ keys(SecretBundle)`:

```
a = AmbientBundle[name]   /* optional */
s = SecretBundle[name]    /* optional */

if a and s both present:           /* collision */
    pick = resolve(name, RoutePolicy)   /* prefer, then first matching rule */
    if pick = error → plan error
    if pick = secret → Merged[name] = s
    if pick = ambient → Merged[name] = a
elif a present:
    Merged[name] = a
else:
    Merged[name] = s
```

`route:prefer` and per-name `route:NAME=` apply **only on collision**. If only
one side supplies a name, that entry is kept without consulting `prefer`.

Rule precedence:

```
1. First matching per-rule entry (declaration order)
2. Global route:prefer
```

### Phase 3 — Demand (final)

```
1. final.reject on env names in keys(Merged) → error if present
2. candidates = all merged names or only-matched names
3. subtract final.omit (remove from child env)
4. final.require → error if missing from candidates
5. ChildEnv = { name → Merged[name] | name ∈ candidates }
```

### Phase 4 — Execute

1. `fork()`.
2. In child: apply `ChildEnv` via `execvpe` with a constructed environ array.
   `execvpe` is intentional: the command operand may be an unqualified program
   name when `PATH` is present in `ChildEnv`.
3. Parent environ is never modified.
4. Secret plaintext buffers are cleared after copy.

Dry-run stops after Phase 3 plan validation without decrypting secret values.

## 7. CLI

### 7.1 Grammar

```
--inject LAYER:KIND=SELECTOR[:SELECTOR...]
```

Multiple selectors in one `--inject` value are separated by `:` (for example
`ambient:only=PATH:HOME:USER`). This is distinct from the `LAYER:KIND=` token
syntax. `secret:rename` takes a single sed expression and never splits the
value on `:`.

| LAYER | KIND | SELECTOR meaning |
| --- | --- | --- |
| `ambient` | `only`, `omit`, `require`, `reject` | env name or glob |
| `secret` | `only`, `omit`, `require`, `reject` | key name or glob |
| `secret` | `rename` | one sed-style `s///` expression |
| `route` | `prefer` | `secret`, `ambient`, or `error` |
| `route` | `NAME` or `GLOB` | `secret`, `ambient`, or `error` |
| `final` | `only`, `omit`, `require`, `reject` | env name or glob |

Repeated `--inject` accumulates selectors of the same kind.

`route:prefer` may appear once. Per-name route rules may repeat; first match wins.

`--inject-gate` is separate from pentad rules. The only supported value in
Phase 1 is `sandbox`, which applies the store-attribute pre-filter from §10
before secret supply.

`--inject-gate=sandbox` may appear once.

### 7.2 Command shape

```text
secdat [--dir DIR] [--store STORE] exec [--inject ...]... [--inject-file FILE]...
       [--inject-gate GATE]... [--dry-run] [--json] [--json-summary] [--] CMD [ARGS...]
```

### 7.3 Examples

**Baseline** (ambient all + secret all + secret wins on collision):

```sh
secdat exec -- ./app
```

Equivalent explicit form:

```sh
secdat exec \
  --inject route:prefer=secret \
  -- ./app
```

**CI: APP secrets only, keep ambient PATH on collision:**

```sh
secdat exec \
  --inject secret:only=APP_* \
  --inject secret:require=APP_TOKEN \
  --inject route:PATH=ambient \
  --inject route:prefer=secret \
  --inject final:reject=SECDAT_* \
  -- pytest
```

**Forbid dangerous store keys:**

```sh
secdat exec \
  --inject secret:reject=ROOT_TOKEN:ADMIN_* \
  -- deploy.sh
```

**Strict final allowlist:**

```sh
secdat exec \
  --inject ambient:only=PATH:HOME:USER \
  --inject secret:only=APP_TOKEN \
  --inject final:only=PATH:HOME:APP_TOKEN \
  -- ./app
```

**Fail on any unresolved collision:**

```sh
secdat exec \
  --inject route:prefer=error \
  --inject route:APP_*=secret \
  -- ./app
```

### 7.4 Policy file (optional)

For large policies:

```sh
secdat exec --inject-file exec.env.yaml -- ./app
```

CLI `--inject` after the file overrides file entries.

#### `exec.env.yaml` schema

```yaml
gate: sandbox

supply:
  ambient:
    omit: ["SECDAT_*"]
  secret:
    only: ["APP_*"]
    require: ["APP_TOKEN"]
    reject: ["ROOT_TOKEN"]
    rename: "s/^MY_(.*)$/APP_\\1/"

route:
  prefer: secret
  PATH: ambient
  HOME: ambient

demand:
  final:
    require: ["APP_TOKEN"]
    reject: ["AWS_SECRET_ACCESS_KEY"]
```

Top-level `gate` maps to `--inject-gate` (currently only `sandbox`). YAML keys
under `supply` map to pentad kinds. `demand.final` mirrors `final:` CLI rules.
`gate` and `--inject-gate` share the same at-most-once and conflict rules.

## 8. Preflight and JSON

`--dry-run` and `--json` run Phases 0–3 without secret decryption.

```json
{
  "ok": true,
  "domain": "/home/user/project",
  "store": "app",
  "dry_run": true,
  "inject_gate": null,
  "supply": {
    "ambient": {
      "mode": "default",
      "contributed": ["PATH", "HOME"],
      "rejected_present": []
    },
    "secret": {
      "mode": "only",
      "contributed": ["APP_TOKEN"],
      "rejected_present": [],
      "missing_required": []
    }
  },
  "route": {
    "prefer": "secret",
    "collisions": [
      { "name": "API_TOKEN", "picked": "secret" }
    ]
  },
  "final": {
    "mode": "default",
    "present": ["PATH", "HOME", "APP_TOKEN"],
    "missing_required": [],
    "rejected_present": []
  },
  "injected_key_count": 1,
  "argv": ["./app"]
}
```

`collisions` makes collision-only routing observable. Secret values and
plaintext lengths that would reveal content are omitted.

`--json-summary` appends execution metadata (exit status, signal, duration) to
stderr after a real run, using the same plan shape.

## 9. Error Messages (human)

| Condition | Message |
| --- | --- |
| `ambient:reject` match in environ | `exec inject ambient variable must not be present: NAME` |
| `secret:reject` match in VisibleKeys | `exec inject secret key must not be present: KEY` |
| `secret:require` missing | `exec inject required secret key not available for injection: KEY` |
| `ambient:require` missing | `exec inject required ambient variable not available: NAME` |
| `route:prefer=error` collision | `ambient/secret collision on environment variable: NAME` |
| `final:require` missing | `exec inject required variable missing from final child env: NAME` |
| `final:reject` present | `exec inject forbidden variable in final child env: NAME` |
| rename duplicate env | `duplicate environment variable name from secret rename: NAME` |
| invalid env name | `invalid environment variable name from secret rename: NAME` or `key is not a valid environment variable name: KEY` |
| pentad conflict | `exec inject LAYER pentad conflict: require and omit overlap: SELECTOR` (and analogous require/reject or omit/reject forms) |

## 10. Relationship to Store Attributes

Store attributes (`sandbox_inject`, `secret_inject`, `key_visibility`, etc.)
remain **outside** this pentad. They act as a pre-supply filter on
`VisibleKeys` when enabled by `--inject-gate=sandbox` (or domain defaults in
future work).

This document does not redefine attribute semantics.

## 11. Security Notes

- Child receives plaintext in environ; process listing and core dumps remain a
  host concern.
- `final:only` is a strong isolation tool; omitting `PATH` can break the
  child — no implicit keep-list; document required vars explicitly.
- `secret:reject` checks store visibility, not ambient; use `final:reject` to
  catch ambient-only leaks after routing.
- Parent process environ is unchanged; only the child is mutated.

## 12. Implementation Plan

| PR | Scope |
| --- | --- |
| PR-1 | `pentad`, `selector`, parser for `--inject` / `--inject-file` |
| PR-2 | Supply phase: ambient snapshot + secret rename + pentad |
| PR-3 | Route phase: collision detection + `prefer` / per-rule picks |
| PR-4 | Demand phase: final pentad + ChildEnv builder |
| PR-5 | `exec` integration: fork/execvpe, dry-run, JSON, json-summary |
| PR-6 | Legacy flag lowering (§15), deprecation warnings, conflict checks |
| PR-7 | Regression suite for scenarios in §7.3, §15, and error table §9 |
| PR-8 | User docs: `secdat-spec.md`, `secdat.1`, `README.md`, `po/ja.po` |

## 13. Open Questions

1. ~~**`--inject-file` format** — YAML only, or also JSON?~~ **Decided:** YAML only.
   See [ADR 0001](adr/0001-inject-file-yaml-only.md). Programmatic authoring uses
   `--inject`; JSON remains observation-only (`--dry-run --json`, `--json-summary`).
2. **Attribute pre-gate** — default-on for `secret_inject=never`, or opt-in?
3. **`final:only` warning** — warn when `PATH` / `HOME` absent from allowlist?

## 14. Key Decisions

1. Three layers only: supply → route → demand.
2. One pentad vocabulary: `only`, `omit`, `require`, `reject` (+ implicit default).
3. `ambient` for caller OS env; never `parent` in injection context.
4. `route:prefer` is collision-only; values are `secret`, `ambient`, `error`.
5. CLI surface is `--inject LAYER:KIND=...`; demand layer prefix is `final:`.
6. Legacy `exec` selection flags are **deprecated aliases** during migration (§15),
   not a second permanent interface.

## 15. Legacy Option Migration

Legacy flags are **not** kept as undocumented shorthand. They are **deprecated**,
lowered to `--inject` equivalents in the parser, and scheduled for removal.

### 15.1 Rationale

| Approach | Verdict |
| --- | --- |
| Silent shorthand (help omitted, behavior kept forever) | Rejected — two vocabularies, spec drift, duplicated tests |
| Immediate hard removal | Rejected — breaks scripts and existing docs too abruptly |
| **Deprecated lowering** | **Adopted** — one execution engine, explicit migration path |

Legacy options covered only part of the secret supply layer. The new pipeline
always applies ambient inheritance and default `route:prefer=secret`. Lowered
legacy invocations therefore run on the **new baseline**; this is an intentional
behavior change, not a byte-for-byte replay of the old engine.

### 15.2 Flags That Stay Unchanged

These are execution / observability controls, not injection policy:

| Flag | Role |
| --- | --- |
| `--dry-run` | Plan without decrypting secrets or launching the child |
| `--json` | JSON preflight (requires `--dry-run`) |
| `--json-summary` | JSON audit on stderr after a real execution |
| `--` | Operand separator |

### 15.3 Lowering Table (deprecated → canonical)

| Legacy flag | Lowered to | Notes |
| --- | --- | --- |
| `--pattern G` / `-p G` | `--inject secret:only=G` | Repeatable; each occurrence appends |
| `--pattern-exclude G` / `-x G` | `--inject secret:omit=G` | Repeatable |
| `--require-key K` | `--inject secret:require=K` | Repeatable |
| `--env-map-sed EXPR` | `--inject secret:rename=EXPR` | At most once |

### 15.4 Flags Without 1:1 Lowering

| Legacy flag | Replacement | Notes |
| --- | --- | --- |
| `--sandbox-injectable` | `--inject-gate=sandbox` | Applies the §10 bulk `sandbox_inject` pre-filter; not expressible as pentad alone. |

During migration, `--sandbox-injectable` lowers to the same pre-supply filter as
`--inject-gate=sandbox`. Document the legacy flag only under Migration; do not
list it in the canonical exec reference.

### 15.5 Parser Behavior

```
parse_exec():
  1. Reject legacy flags with replacement hints (Phase 3)
  2. Collect --inject / --inject-file → inject_ir[]
  3. Build supply / route / demand from inject_ir
```

Implementation must use **one** plan builder. Do not maintain parallel legacy
and modern execution paths.

### 15.6 Legacy + `--inject` Together

| Situation | Result |
| --- | --- |
| Legacy and `--inject` touch **different** concerns | Allowed. Example: `-p APP_*` + `--inject route:PATH=ambient` |
| Legacy and `--inject` specify the **same** pentad kind on `secret` | Error. Example: `-p APP_*` + `--inject secret:only=OTHER_*` |
| `--env-map-sed` + `--inject secret:rename=...` | Error (both set rename) |
| `--sandbox-injectable` + `--inject-gate=sandbox` | Error (both set pre-gate) |
| Multiple `--env-map-sed` | Error (unchanged) |
| Multiple `--inject-gate=sandbox` | Error (unchanged) |

### 15.7 Deprecation Warning

Emit once per `exec` invocation when any legacy selection flag is used.
Multiple legacy flags produce one combined warning listing all replacements:

```text
warning: exec: --pattern is deprecated; use --inject secret:only=GLOB; --pattern-exclude is deprecated; use --inject secret:omit=GLOB
```

### 15.8 Migration Timeline

| Phase | Release target | Behavior |
| --- | --- | --- |
| **Phase 1** | First `--inject` release | Legacy flags work via lowering; deprecation warnings on stderr |
| **Phase 2** | Following minor releases | User docs and help show `--inject` only; legacy documented in Migration appendix |
| **Phase 3** | Current | Legacy flags removed; exit code 2 with replacement hint |

### 15.9 Documentation During Migration

- **Canonical reference**: §7 CLI, `--inject` grammar only.
- **Migration appendix**: lowering table (§15.3), behavior change note (§15.1),
  and `--sandbox-injectable` replacement status (§15.4).
- **Do not** document legacy flags in primary help examples or `secdat help exec`
  usage columns after Phase 2.

### 15.10 Regression Requirements

- Each row in §15.3 lowers to an equivalent plan (same `secret` pentad IR).
- Combined legacy + `--inject` conflict cases in §15.6 fail before planning.
- Lowered legacy invocation under new baseline: ambient inherited, default
  `route:prefer=secret`, unless explicit `--inject route:...` overrides.
- Phase 3 removal: specifying a legacy flag fails with a message naming the
  `--inject` replacement.