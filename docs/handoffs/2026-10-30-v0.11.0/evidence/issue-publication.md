ユーザーの後続指示「では、リリースお願いします。」を受け、検証済み候補を公開しました。

- Release: https://github.com/mako10k/secdat/releases/tag/v0.11.0
- main / release commit: `0e4eb24eba841a901dd6b320cbb3eb71ddf37f97`
- tree: `704a660340df464f159b500591eb2edd7edf581f`
- 注釈付きタグ object: `c590167ae3ff16a9ed03f4829d1b09ef5d2708d4`
- Release ID: `428988273`（2026-10-30 21:07:39 JST 公開）

main push・tag push・Release create はそれぞれ1回で成功し、リモート main、タグ object、peeled commit、Release の名前・正確な本文・対象SHA・draft/prerelease=false・明示assets=0、および最新の正式Releaseであることを読み戻して確認しました。ローカル main と origin/main も同じSHAへfast-forward済みです。候補の変更、force、再試行、全体gateの再実行は行っていません。

既知の制限は公開したリリースノートにそのまま含まれています。準備段階の公開禁止境界は後続のユーザー指示で解除されたものであり、当時の履歴は保持しています。

公開receiptとreadbacksは `/home/katsumata-m/secdat-release-evidence/v0.11.0/publication-result.json`、`PUBLICATION-RESULT.md` に保存しました。パッケージregistryへのpublishや通常環境へのinstallは今回のGitHub Releaseには含めていません。
