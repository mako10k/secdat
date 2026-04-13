# secdat Repository Instructions

## Workflow

- Treat GitHub issues as the source of truth for implementation work.
- Capture new implementation requests as issues before changing code.
- Prefer the highest-priority open issue unless the user explicitly redirects the order.
- After implementation, verify the change, comment on the issue with the result, and close it when the accepted scope is complete.
- If new ideas appear while closing an issue, move them into a new issue instead of stretching the current one.

## Validation

- Prefer a focused check immediately after the first code change for a slice.
- Use `make` for narrow build validation.
- Use the nearest regression script when a feature already has one.
- Run `make check` before closing an implementation issue when the change affects behavior.

## Project Knowledge

- `KEYREF` is the canonical targeting syntax: `KEY[/ABSOLUTE/DOMAIN][:STORE]`.
- Do not add destination-specific `cp` or `mv` flags when `KEYREF` qualification already expresses the target.
- The first interactive `unlock` generates a fresh master key, wraps it with the passphrase, and stores the wrapped copy under `XDG_DATA_HOME`.
- `SECDAT_MASTER_KEY` remains an explicit override or migration source, not the default first-use path.
- Normal secret access uses the wrapped-key plus session-agent flow; `status`, `unlock`, and `lock` are the recovery path for session problems.
- Session regressions can use `SECDAT_SESSION_IDLE_SECONDS` to force short expiry behavior.
- `export` is bash-oriented and must not print raw secret values directly.
- `export` should reuse `get --shellescaped` for secret-value quoting.
- Exported keys must already be valid shell identifiers; do not silently normalize them.

## Editing Guidance

- Keep changes minimal and local to the issue being implemented.
- Preserve the current CLI and wording style unless the issue requires a behavior change.
- Update `README.md`, `docs/secdat-spec.md`, tests, and `po/ja.po` when user-facing behavior changes.