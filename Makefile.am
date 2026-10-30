SUBDIRS = po src
dist_doc_DATA = README.md docs/secdat-spec.md
dist_man1_MANS = docs/secdat.1
if ENABLE_FUSE
dist_man1_MANS += docs/secdat-fuse.1
endif
dist_noinst_DATA = completions/secdat.bash
bashcompletiondir = $(datadir)/bash-completion/completions
binding_dist_files = \
	bindings/README.md \
	bindings/go/README.md \
	bindings/go/go.mod \
	bindings/go/secdat/pkg_config_shared.go \
	bindings/go/secdat/pkg_config_static.go \
	bindings/go/secdat/secdat.go \
	bindings/node/README.md \
	bindings/node/binding.gyp \
	bindings/node/index.js \
	bindings/node/package-lock.json \
	bindings/node/package.json \
	bindings/node/src/addon.cc \
	bindings/python/README.md \
	bindings/python/pyproject.toml \
	bindings/python/secdat_sdk.py \
	bindings/rust/Cargo.lock \
	bindings/rust/Cargo.toml \
	bindings/rust/README.md \
	bindings/rust/build.rs \
	bindings/rust/src/lib.rs
sealgraph_dist_files = \
	.sealgraph/.gitignore \
	.sealgraph/config \
	.sealgraph/index/adr/0006/.track \
	.sealgraph/index/adr/0007/.track \
	.sealgraph/index/adr/0008/.track \
	.sealgraph/index/adr/0009/.track \
	.sealgraph/index/adr/0010/.track \
	.sealgraph/locks/.gitkeep \
	.sealgraph/objects/19/0aed53ffdbb036fe7ea053f74a26c1c0f6d1845ad6b4423c13fbc436f8addb \
	.sealgraph/objects/24/7c1b858c39a4db2a2e981a780b8499f2da8ce8af93e62f28f465bd5ee4aa95 \
	.sealgraph/objects/39/6b74b3b9260759d7ef45121721cd7ba66d1bb6aa50ab547feae65e5bb4c854 \
	.sealgraph/objects/55/a613c425357096b52c6ddea21cff8ac0955d25d312d036d3ac4d4567cfe767 \
	.sealgraph/objects/6a/7b4bbba875cf8f256145874442d773b0fd34b4a078d51f22c91c4d5e368555 \
	.sealgraph/objects/72/5e8d7cf0ff060c5eef3f2542f74a20d3a8b0ad9932a8a49bfe0d0b48441ac0 \
	.sealgraph/objects/83/99f477daffc38555732c577790bb53d7d161d30095e824c856a386a6927bc6 \
	.sealgraph/objects/88/dcbc1649ca583c349113ec26622a90bc78d16ed49a614982672db6e548627c \
	.sealgraph/objects/8d/07c23e8af704fee86cce7a70588e4558b70b1fb68420b6af5feaf5ab4ea2a6 \
	.sealgraph/objects/95/80a219fa61f32910469d391513bf53893198053891ee3c7dc9aa9e18f45976 \
	.sealgraph/objects/aa/a421f598b965be7914798c71a7973ddd9b7f7d3f7909cb23b09d27bb468988 \
	.sealgraph/objects/bb/77a50c2a21597ceb9dfc74bdae8aca7ba332353f6b01e93d75a21a39516d89 \
	.sealgraph/objects/bb/a63d297932c4f59e8393f91e5e1cc349ccda8a9247e82b54b14b324be73f16 \
	.sealgraph/objects/f1/190efca89216bb3880d86245cd715ebd3f8eb322419f7b2e0e5412b39207a6 \
	.sealgraph/refs/seals/adr/0006/.ref \
	.sealgraph/refs/seals/adr/0007/.ref \
	.sealgraph/refs/seals/adr/0008/.ref \
	.sealgraph/refs/seals/adr/0009/.ref \
	.sealgraph/refs/seals/adr/0010/.ref
EXTRA_DIST = .gitignore $(binding_dist_files) $(sealgraph_dist_files) completions/secdat.bash contrib/secdat-askpass docs/secdat-fuse.1 docs/release-workflow.md docs/adr/0006-uuid-stable-mv-and-identity-linked-masks.md docs/adr/0007-lifecycle-timestamps-and-list-display.md docs/adr/0008-persistent-session-agent-deferred-gc.md docs/adr/0009-scoped-mutation-preparation-and-direct-write-sets.md docs/adr/0010-semantic-gc-owner-queue-emptiness.md plans/adr-0006-implementation.pert plans/secret-generation-bundles.pert plans/lifecycle-gc-scoped-mutations.pert plans/orphan-domain-delete.pert docs/release-notes/v0.2.1.md docs/release-notes/v0.2.2.md docs/release-notes/v0.3.0.md docs/release-notes/v0.4.0.md docs/release-notes/v0.4.1.md docs/release-notes/v0.4.2.md docs/release-notes/v0.5.0.md docs/release-notes/v0.6.0.md docs/release-notes/v0.6.1.md docs/release-notes/v0.7.0.md docs/release-notes/v0.8.0.md docs/release-notes/v0.9.0.md docs/release-notes/v0.10.0.md tests/ephemeral_contract_matrix.md tests/gettext_catalog_regression.sh tests/release_metadata_regression.sh tests/static_analysis_contract_regression.sh tests/static_analysis_regression.sh tests/libtool_relink_regression.sh tests/abi_regression.sh tests/build_id_regression.sh tests/keyref_regression.sh tests/session_agent_cleanup.py tests/session_test_cleanup.sh tests/session_regression.sh tests/sdk_regression.sh tests/e2e_regression.sh tests/save_load_regression.sh tests/generate_regression.sh tests/export_regression.sh tests/lower_level_regression.sh tests/completion_regression.sh tests/install_regression.sh tests/attribute_regression.sh tests/metadata_relation_regression.sh tests/fsck_regression.sh tests/v2_fsck_regression.sh tests/deferred_gc_regression.sh tests/dependency_index_regression.sh tests/container_transaction_regression.sh tests/domain_move_transaction_regression.sh tests/mv_transaction_regression.sh tests/mask_identity_regression.sh tests/mask_transaction_regression.sh tests/mask_mutation_regression.sh tests/scoped_set_regression.sh tests/scoped_mutation_scale_regression.sh tests/scoped_mutation_performance.sh tests/migrate_regression.sh tests/inject_regression.sh tests/redaction_regression.sh tests/fuse_regression.sh

if BUILD_SHARED_LIBSECDAT
sdk_shared_library = $(abs_top_builddir)/src/.libs/libsecdat.so
else
sdk_shared_library =
endif

install-data-local:
	$(MKDIR_P) "$(DESTDIR)$(bashcompletiondir)"
	$(INSTALL_DATA) "$(srcdir)/completions/secdat.bash" "$(DESTDIR)$(bashcompletiondir)/secdat"

install-exec-local:
	@if test -z "$(DESTDIR)" && command -v ldconfig >/dev/null 2>&1; then \
		case "$(libdir)" in \
			/lib*|/usr/lib*|/usr/local/lib*) ldconfig ;; \
		esac; \
	fi

uninstall-local:
	rm -f "$(DESTDIR)$(bashcompletiondir)/secdat"
	@if test -z "$(DESTDIR)" && command -v ldconfig >/dev/null 2>&1; then \
		case "$(libdir)" in \
			/lib*|/usr/lib*|/usr/local/lib*) ldconfig ;; \
		esac; \
	fi

install-askpass-helper:
	$(MKDIR_P) "$(DESTDIR)$(libexecdir)/secdat"
	$(INSTALL_SCRIPT) "$(srcdir)/contrib/secdat-askpass" "$(DESTDIR)$(libexecdir)/secdat/secdat-askpass"

uninstall-askpass-helper:
	rm -f "$(DESTDIR)$(libexecdir)/secdat/secdat-askpass"

.PHONY: install-askpass-helper uninstall-askpass-helper

all-local:
	@set -e; \
	for po in "$(srcdir)"/po/*.po; do \
		if test -f "$$po"; then \
			lang=`basename "$$po" .po`; \
			if test ! -f "po/$$lang.gmo" || test "$$po" -nt "po/$$lang.gmo"; then \
				$(MAKE) -C po "$$lang.gmo"; \
			fi; \
		fi; \
	done; \
	for catalog in "$(srcdir)"/po/*.gmo po/*.gmo; do \
		if test -f "$$catalog"; then \
			lang=`basename "$$catalog" .gmo`; \
			dir="$(abs_top_builddir)/po/.locale/$$lang/LC_MESSAGES"; \
			mkdir -p "$$dir"; \
			rm -f "$$dir/$(PACKAGE).mo"; \
			cp "$$catalog" "$$dir/$(PACKAGE).mo"; \
		fi; \
	done

check-local:
	$(MAKE) all-local
	bash $(srcdir)/tests/gettext_catalog_regression.sh "$(abs_top_srcdir)"
	bash $(srcdir)/tests/release_metadata_regression.sh "$(abs_top_srcdir)"
	bash $(srcdir)/tests/static_analysis_contract_regression.sh "$(abs_top_srcdir)"
	bash $(srcdir)/tests/static_analysis_regression.sh "$(abs_top_srcdir)"
	bash $(srcdir)/tests/libtool_relink_regression.sh "$(abs_top_builddir)"
if BUILD_SHARED_LIBSECDAT
	bash $(srcdir)/tests/abi_regression.sh "$(abs_top_builddir)/src/.libs/libsecdat.so"
else
	@printf 'SKIP ABI regression: shared libraries disabled\n'
endif
	bash $(srcdir)/tests/build_id_regression.sh "$(abs_top_srcdir)"
	bash $(srcdir)/tests/lower_level_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/keyref_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/attribute_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/metadata_relation_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/fsck_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/v2_fsck_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/deferred_gc_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/dependency_index_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/container_transaction_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/domain_move_transaction_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/mv_transaction_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/mask_identity_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/mask_transaction_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/mask_mutation_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/scoped_set_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/scoped_mutation_scale_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/migrate_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/session_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/install_regression.sh "$(abs_top_builddir)" "$(abs_top_srcdir)"
	bash $(srcdir)/tests/sdk_regression.sh "$(abs_top_builddir)/src/secdat" "$(sdk_shared_library)"
	bash $(srcdir)/tests/redaction_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/completion_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/e2e_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/save_load_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/generate_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/export_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/inject_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/fuse_regression.sh "$(abs_top_builddir)/src/secdat" "$(abs_top_builddir)/src/secdat-fuse"

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsecdat.pc

clean-local:
	rm -rf $(abs_top_builddir)/po/.locale
