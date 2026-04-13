SUBDIRS = po src
dist_doc_DATA = README.md docs/secdat-spec.md
EXTRA_DIST = tests/keyref_regression.sh tests/session_regression.sh tests/e2e_regression.sh

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
	bash $(srcdir)/tests/keyref_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/session_regression.sh "$(abs_top_builddir)/src/secdat"
	bash $(srcdir)/tests/e2e_regression.sh "$(abs_top_builddir)/src/secdat"

clean-local:
	rm -rf $(abs_top_builddir)/po/.locale
