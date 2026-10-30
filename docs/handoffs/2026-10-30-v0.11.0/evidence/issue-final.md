v0.11.0 のリリース準備と必要な検証を完了しました。最終判断は **既知の制限を明示したうえで公開可能（GO）** です。タグ作成・公開は実施していません。

候補: `0e4eb24eba841a901dd6b320cbb3eb71ddf37f97`
Tree: `704a660340df464f159b500591eb2edd7edf581f`
ローカルブランチ: `codex/release-0.11.0`（未 push、remote main `c465ab9` から1コミット）。core/bindings/lockfiles/Rust最低版/man/gettext を0.11.0へ更新し、リリースノートを配布物へ追加、旧仕様のv2既定に関する矛盾を修正しました。ABI/SONAMEは維持しています。

検証軸:
- fresh gettext・release metadata・build、FUSE有効make check PASS。実mountの読書き/readbackと/tmp配置で日本語locale確認を含みます。
- FUSE有効default/shared-only/static-onlyのserial make distcheckが全てPASS。
- 配布アーカイブの追跡対象117ファイルを候補Git blobと照合。
- 配置済みC shared/static consumerのcompile/link/runtime、Python source wrapper＋wheelの隔離install/runtime/version、Rust locked check/package verify、Node build/pack＋外部tarball consumer、Go shared/static link/runtime、pkg-configを確認。
- 最終reviewerが同じclean候補と12試行のreceipt/log/resource/input hashes、18生成物hash、117ソース比較、正確なrelease-note blob/bodyを読取り確認し、指摘なし。

失敗試行は隠さず保持しています。並列distcheckのpath-query問題は #248 に分離し、文書どおりserial実行でPASS。bindings統合試行09は、Python/Rust/Nodeの成功後にGoのVCS自動検出で失敗したため全体FAILのままです。無関係な空のHOME/.gitが原因で、配布物consumer限定の-buildvcs=falseを指定したGo専用試行10で残りのshared/static軸がPASSしました。ホームやglobal設定・製品候補は変更していません。

既知の制限: #221の同一protocol handover XFAIL、#242の孤立renamed-domain移動失敗、未完の#166–#169、mixed-format mask曖昧性ガード、明示index repair要件をリリースノートに明記。distcheck prefixによるlocale SKIPはmake checkの/tmp配置で確認済み、static-onlyの共有ABI/Python SKIPは共有構成とwheelで補っています。Rust/npmの非fatal警告はraw logに残しておりregistry publicationは範囲外です。

永続証拠: `/home/katsumata-m/secdat-release-evidence/v0.11.0/FINAL-JUDGMENT.md`、`matrix-summary.json`、`publication-inputs.json` と個別receipts/logs/artifacts。測定gate全試行合計73分51秒、CPU47分01秒、最大RSS487188KiB（準備・診断を含む全作業時間や人時ではありません）。

次の公開操作はユーザーの最終判断後です。正確な候補をmainへ反映・readbackし、候補identityを維持したままタグ/Release手順へ進む必要があります。新しいmerge commitや候補編集へreceiptを流用しません。今回main/tag/Releaseの書込み、通常環境へのinstallはありません。
