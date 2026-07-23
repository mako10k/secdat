# ADR 0006 / Issue #164 WIP 引継ぎ

作成日: 2026-07-23

対象: [Issue #164: Preserve masks and report mutation impacts](https://github.com/mako10k/secdat/issues/164)

基点コミット: `29e2535 Add recoverable identity mask writes`

## 状態

`plans/adr-0006-implementation.pert` の `MASK_IMPACT_WRITES` は `active` のまま。
Issue #164 も open のままであり、この WIP は受け入れ完了、レビュー完了、または
`make check` 完了を意味しない。

現在の作業ツリーには、v2 の `set` / `cp` / `ln` / `rm` / `load` と
multi-set に共通の mask mutation plan を適用する途中実装がある。

## WIP で実装済みの範囲

- `--mask-action=preserve|reject` と、
  `--mask-warnings=default|on|off` / `--warn-mask` / `--no-warn-mask` を
  実動作と直交する共通 policy として追加した。
- `--dry-run` と `--json` が commit と同じ
  `secdat.mutation-plan.v1` を使うようにした。
- v2 persisted store では保護された state snapshot 上で command 全体を実行し、
  concrete slot ごとに `require_complete=1` で mask impact を解析した。
- canonical public mask の compatibility tombstone を再整合し、
  canonical hidden mask は canonical-only を維持した。
- state file 差分を既存 journal transaction に載せ、
  multi-set / load を含めて all-before/all-after にする基盤を追加した。
- `direct-hit`、`became-dormant`、`reactivated`、`orphaned`、
  `source-mask-created`、`legacy-ambiguous` を plan 上で扱うようにした。
- 成功時の既定警告は非ゼロの事実だけを平易な文面で出し、
  警告抑制が plan、state、status を変えないようにした。
- help、completion、README、spec、manpage、日本語翻訳と
  `tests/mask_mutation_regression.sh` を追加・更新した。
- analyzer 失敗時に wrapper status が 0 のままになる不具合と、
  recovery loader が新しい operation 名を拒否する不具合を修正した。

## 確認済み

- `make -j2 CFLAGS='-g -O2'`: PASS
- `tests/mask_mutation_regression.sh`: PASS
  - 最後の警告文言変更前に実行済み。期待値は変更済みだが再実行は未実施。
- `tests/mask_identity_regression.sh`: PASS
- `tests/mask_transaction_regression.sh`: PASS
- `tests/session_regression.sh`: PASS
- `tests/keyref_regression.sh`: PASS
- `tests/e2e_regression.sh`: PASS
- `tests/completion_regression.sh`: PASS
- `msgfmt --check -o /tmp/secdat-ja.gmo po/ja.po`: PASS
  - 最後の警告文言 7 件を翻訳する前の結果なので再実行が必要。

## 既知の失敗と未完了

- `tests/save_load_regression.sh` は `load --help` の確認だけ失敗する。
  既存テストが usage 内の連続文字列 `load FILE` を期待する一方、
  新しい mask option が `load` と `FILE` の間に入ったため。
- 最終ソース・文書・翻訳に対するレビューは未実施。
- `make check CFLAGS='-g -O2'` は未実施。
- base store が v1 で、明示 KEYREF の destination だけが v2 の場合、
  planner を迂回して旧動作へ fallback する可能性がある。store-format 判定位置を
  acceptance 前に確認する。
- generic state transaction は rollback 後に空の親 directory を残す可能性がある。
  内容の all-before/all-after だけで十分か、directory cleanup まで契約に含めるか
  レビューする。
- transaction target 上限を 4096 に拡張した。大規模 load / multi-set の扱いを
  明文化または検証する。
- volatile overlay は既定の旧動作のみで、明示 planning option は拒否する。
  persisted v2 限定という仕様記述と実装の整合をレビューする。
- JSON row は ID と state を持つが、`cp` / `ln` の source/destination identity
  までは持たない。ADR の共通 JSON 契約に必要か確認する。
- snapshot は global transaction lock 内で state 全体を clone するため、
  store 規模に対する性能と lock 保持時間のレビューが必要。
- `source-mask-created` は `rm` に実装済みだが、`fallback-remasked` はこの slice
  では未実装。
- `src/store.c` の変更量が大きいため、state snapshot、slot tracking、
  journal apply/recovery、stage cleanup を重点的にレビューする。

## 再開順

1. `git status --short --branch` でこの WIP 以外の変更がないことを確認する。
2. `perttool dsl check plans/adr-0006-implementation.pert` と
   `perttool dag next plans/adr-0006-implementation.pert` を実行し、
   `MASK_IMPACT_WRITES` が active であることを確認する。
3. `tests/save_load_regression.sh` の help marker を、新 usage 契約に合わせて直す。
4. 上記の未完了設計点、特に明示 v2 destination の format 判定と
   state transaction の recovery/cleanup をレビューして必要な修正を行う。
5. `make -j2 CFLAGS='-g -O2'`、`msgfmt --check`、focused regression
   (`mask_mutation`、`mask_identity`、`mask_transaction`、`save_load`、
   `completion`、`e2e`) を再実行する。
6. `make check CFLAGS='-g -O2'` を完了する。
7. 設計整合性レビューと user-eye review を行い、指摘を解消する。
8. acceptance を満たした場合に限り PERT task を `done` にし、
   Issue #164 に検証結果を記録して close し、non-WIP commit を作る。

## 変更対象

- `src/store.c`
- `src/cli.c`
- `tests/mask_mutation_regression.sh`
- `Makefile.am`
- `README.md`
- `docs/secdat-spec.md`
- `docs/secdat.1`
- `po/ja.po`
- `tests/e2e_regression.sh`（末尾改行のみ）
