SUBDIRS = po src
dist_doc_DATA = README.md docs/secdat-spec.md
man1_MANS = docs/secdat.1
dist_noinst_DATA = completions/secdat.bash
bashcompletiondir = $(datadir)/bash-completion/completions
EXTRA_DIST = completions/secdat.bash tests/keyref_regression.sh tests/session_regression.sh tests/e2e_regression.sh tests/save_load_regression.sh tests/export_regression.sh tests/lower_level_regression.sh

install-data-local:
	$(MKDIR_P) "$(DESTDIR)$(bashcompletiondir)"
	$(INSTALL_DATA) "$(srcdir)/completions/secdat.bash" "$(DESTDIR)$(bashcompletiondir)/secdat"

uninstall-local:
	rm -f "$(DESTDIR)$(bashcompletiondir)/secdat"

all-local:
	@set -e; \
	for po in po/*.po; do \
		if test -f "$$po"; then \
			lang=`basename "$$po" .po`; \
			if test ! -f "po/$$lang.gmo" || test "$$po" -nt "po/$$lang.gmo"; then \
				$(MAKE) -C po "$$lang.gmo"; \
			fi; \
		fi; \
	done; \
	for catalog in po/*.gmo; do \
		if test -f "$$catalog"; then \
			lang=`basename "$$catalog" .gmo`; \
			dir="$(abs_top_builddir)/po/.locale/$$lang/LC_MESSAGES"; \
			mkdir -p "$$dir"; \
			cp "$$catalog" "$$dir/$(PACKAGE).mo"; \
		fi; \
	done

check-local:
	bash $(srcdir)/tests/lower_level_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/keyref_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/session_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/e2e_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/save_load_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/export_regression.sh "$(abs_top_builddir)/src/secdat"

clean-local:
	rm -rf $(abs_top_builddir)/po/.locale
