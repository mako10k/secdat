SUBDIRS = po src
dist_doc_DATA = README.md docs/secdat-spec.md

all-local:
	@set -e; \
	for catalog in po/*.gmo; do \
		if test -f "$$catalog"; then \
			lang=`basename "$$catalog" .gmo`; \
			dir="$(abs_top_builddir)/po/.locale/$$lang/LC_MESSAGES"; \
			mkdir -p "$$dir"; \
			cp "$$catalog" "$$dir/$(PACKAGE).mo"; \
		fi; \
	done

clean-local:
	rm -rf $(abs_top_builddir)/po/.locale
