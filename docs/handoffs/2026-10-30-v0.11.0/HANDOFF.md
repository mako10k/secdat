# 2026-10-30 secdat v0.11.0 closeout

本日の closeout 指示に基づく保全スナップショット。新規実装・本番変更・追加リリースは開始しない。このブランチは資料保全のみで、main への merge は行わない。

## 完了した担当範囲

- #243 store 名 Bash 補完: PR #245 merge 済み。実装 commit `101905abd66075928722d6e3080ea6a71a4cac43`、merge `783bd37af2d2d15d2714a5a8033921b838374e02`。
- #244 新規ストア v2 既定化・fsck 形式自動判定: PR #246 merge 済み。候補 `44173e79a6f12f0c6f60b4747c4170bc1289f38e`、merge `c465ab9e05a15a1b8054f52a402e93cfe006366d`。既存 v1 自動移行・新規 v1 作成オプションは追加していない。混在形式 mask の既存制約は所有者の明示選択で維持した。
- #247 v0.11.0 準備: 版数・notes を揃え、FUSE 有効 make check、default/shared-only/static-only serial distcheck、配置済み C/Python/Rust/Node/Go consumer と package の必要軸を検証。独立最終レビューに未解決 blocker なし。
- 後続の明示指示で GitHub Release を公開済み。URL: https://github.com/mako10k/secdat/releases/tag/v0.11.0 。main / release commit は `0e4eb24eba841a901dd6b320cbb3eb71ddf37f97`、tree `704a660340df464f159b500591eb2edd7edf581f`。注釈付き tag object は `c590167ae3ff16a9ed03f4829d1b09ef5d2708d4`。Release ID `428988273`。main・tag object・peeled commit・正確な notes 本文・正式/最新状態を読み戻した。main push、tag push、Release create は各1回で成功、force/retry なし。
- さらに明示指示でローカル `/usr/local` に同じ v0.11.0 を FUSE 有効で install 済み。通常 PATH は `/usr/local/bin/secdat`、表示 `secdat 0.11.0` / `Build: 0e4eb24eba84`。stage と配置先の15ファイル一致、共有ライブラリ参照先と pkg-config 版数を確認した。
- installed binary に対する Bash completion regression は PASS。通常 interactive Bash の自動読込みが `/usr/local/share/bash-completion/completions/secdat` を選ぶこと、親を含む `--store`・ローカル限定管理操作・空白・attached `--store=`・create 非候補・fixture 状態不変を確認。既に開いている Bash の定義更新には `source /usr/local/share/bash-completion/completions/secdat` を案内済み。

## 証拠の位置・意味

原本: `/home/katsumata-m/secdat-release-evidence/v0.11.0/`（約200MB）。本ブランチの `evidence/` は138個のテキスト/receipt/log/script/plan のバイト同一スナップショットで、`SNAPSHOT-MANIFEST.json` に原本位置・サイズ・SHA256を記録した。元 receipt の絶対パス・candidate identity・FAIL/PASS は書き換えていない。

- `evidence/FINAL-JUDGMENT.md`, `matrix-summary.json`: 検証軸・限界・資源実績。測定 gate 全試行73m51s、CPU47m01s、peak RSS487188KiB。準備・診断を含む全作業時間や人時ではない。
- `evidence/publication-result.json`, `PUBLICATION-RESULT.md`: 公開結果と読み戻し。
- `evidence/local-install/result.json`, `RESULT.md`: 実 install と補完検証。
- `evidence/plans/`: ignored build 配下だった計画の保全。release 計画の元の目的は準備までであり、後続の公開/install 指示・実行は上記の別 receipt が示す。過去の「公開未承認」を現在状態に読み替えない。

巨大/再生成可能な build、依存 cache、test fixture data、配布 tar・native objects・wheel/tgz/crate 等の生成物、旧 install backup tar は Git へ含めず原本領域に保持した。生成物18個の hash は matrix summary にあり、旧15ファイルの復旧用 archive は `local-install/previous-install.tar`、対象は `install-manifest.json` にある。これらの bytes がこの Git snapshot に揃っているとは主張しない。credential 注入 preflight JSON も同期対象外。削除・自動復旧はしていない。

## FAIL・既知制限を消さない

- parallel distcheck の試行05は FAIL のまま。継承 make flags による path query 汚染を #248 に分離し、文書の serial05b が PASS。製品候補は未変更。
- bindings09は Python/Rust/Node の成功後に Go VCS stamp で失敗したため overall FAIL。Go が空の HOME/.git を拾う環境要因を切り分け、配布 consumer 限定 `-buildvcs=false` の10で shared/static build/link/runtime を完了。HOME/global 設定は変更していない。
- original01–04の checker/environment hash は事後 inventory であり、実行時取得と偽らない。後続 receipt は実行時 hash を保持する。
- #221 handover XFAIL、#242 孤立 renamed-domain move、#166–#169 未完範囲、mixed-format mask guard は release notes に明記済み。registry publish は行っていない。
- local install の長い runtime path と set-e callback の失敗した smoke も原形で保持。短い `/tmp` runtime と通常の補完呼出し条件で期待値・不変性を検証済み。稼働中ユーザー agent の再起動、shell rc 編集、既存ストア移行はしていない。

## 担当ツリー・配下担当

- release tree `/home/katsumata-m/secdat-release-0.11.0`: `codex/release-0.11.0`、HEAD0e4eb24、clean。main と同内容、独自の未保全コードなし。
- install source tree `/home/katsumata-m/secdat-install-0.11.0`: detached0e4eb24、clean。再現用ソース/ビルドを保持。
- issue243/244 trees: それぞれ101905a/44173e7、clean、担当コードは main に到達済み。
- `/root/completion_design_review` は読取専用レビュー完了、`/root/store_completion_tests` の test 変更も全て担当 commit に統合済み。両者 idle/completed、実行中の担当 build/test なし。

## 所有不明 WIP の別ブランチ保全（元作業場不変）

初回の担当外除外の報告後、追加の明示指示で「実装/採用/統合せず、所有不明を明記して別 WIP branch に保存」が許可された。以下の保存だけを実施した。元担当の所有・検証・再開条件は依然不明であり、完成/採用の証拠にはしない。

### GC/domain の元 dirty 作業場

元 `/home/katsumata-m/secdat` は branch `codex/adr-0010-gc-owner-queue-emptiness` / HEAD `1aa50367d91e14b2d8beece3f09f57986845af8a` のまま。以下9ファイルの読取り前後の HEAD・status・bytes が一致することを確認し、別worktreeへ同一内容を適用した。元作業場では checkout/reset/stash/index変更やファイル編集をしていない。

- `Makefile.am`, `docs/secdat-spec.md`, `po/ja.po`, `po/secdat.pot`
- `src/domain.c`, `src/store.c`
- `tests/container_transaction_regression.sh`, `tests/deferred_gc_regression.sh`
- untracked だった `plans/orphan-domain-delete.pert`

保存先: `codex/wip-gc-domain-20261030` / `67ea64bb33f70591bb1fa2d088d4f4f5e8ca2913`。
remote SHA 読戻し済み。WIP commit として保存しただけで、build/test/review/merge は行っていない。元の dirty 状態は意図して残しているため、git status が dirty でもこの9ファイルの captured snapshot は remote に到達済み。snapshot manifest は `evidence/closeout/gc-domain-source.json`。その後新たな編集があれば別途保全が必要。

### 旧 v0.5.0 WIP

元 local branch `wip/v0.5.0-release-20260806` は `8bd26e2629ab34c1b2a3ea4701fa497d8b4fc6dc`。元 remote branch は実読取りで `f430317891cf868aef5412a62636ed91e252e065`、差は4コミットだった。

保存先: `codex/wip-v0.5.0-snapshot-20261030` / `8bd26e2629ab34c1b2a3ea4701fa497d8b4fc6dc`。
remote SHA 読戻し済み。元 branch の履歴・ref は書換えず、既存 WIP tip をそのまま別 ref に push した。新しい実装・修正・重複commitは作らず、所有/現行適用性/検証状態は未確認のまま保持する。

上記保全対象の変更/未同期コミットについて credential/private-key パターンを確認したが、内容の正しさや秘密不在を一般に証明する意味へ拡張しない。readback は `evidence/closeout/wip-remote-readback.txt`。この資料保全 branch とともに main/Releaseへmergeしない。

## 再開境界

今回の担当依頼は完了。再開は新しい所有者指示から行い、未完 backlog を自動実装しない。保全専用 branch の commit/push/readback は closeout 実行側の最終報告を参照。公開済み tag や main をこの資料 commit へ動かさない。共有 worktimectl stop/end は操作していない。
