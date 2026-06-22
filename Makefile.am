SUBDIRS = po src
dist_doc_DATA = README.md docs/secdat-spec.md
dist_man1_MANS = docs/secdat.1
dist_noinst_DATA = completions/secdat.bash
bashcompletiondir = $(datadir)/bash-completion/completions
EXTRA_DIST = completions/secdat.bash docs/release-workflow.md docs/release-notes/v0.2.1.md docs/release-notes/v0.2.2.md tests/keyref_regression.sh tests/session_regression.sh tests/sdk_regression.sh tests/e2e_regression.sh tests/save_load_regression.sh tests/export_regression.sh tests/lower_level_regression.sh tests/completion_regression.sh tests/attribute_regression.sh tests/metadata_relation_regression.sh tests/fsck_regression.sh tests/v2_fsck_regression.sh tests/migrate_regression.sh

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
	bash $(srcdir)/tests/lower_level_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/keyref_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/attribute_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/metadata_relation_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/fsck_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/v2_fsck_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/migrate_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/session_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/sdk_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/completion_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/e2e_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/save_load_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/export_regression.sh "$(abs_top_builddir)/src/secdat"

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsecdat.pc

clean-local:
	rm -rf $(abs_top_builddir)/po/.locale
