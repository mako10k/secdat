SECDAT_BUILD_ID = $(shell cd $(top_srcdir) >/dev/null 2>&1 && if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then hash=$$(git rev-parse --short=12 HEAD 2>/dev/null || true); if test -n "$$hash"; then if test -n "$$(git status --porcelain --untracked-files=normal 2>/dev/null)"; then printf '%s' "$$hash-dirty"; else printf '%s' "$$hash"; fi; fi; fi)

AM_CPPFLAGS = \
	-DLOCALEDIR=\"$(localedir)\" \
	-DPACKAGE_NAME=\"$(PACKAGE)\" \
	-DSECDAT_BUILD_ID=\"$(SECDAT_BUILD_ID)\" \
	$(OPENSSL_CFLAGS)

bin_PROGRAMS = secdat
secdat_LDADD = $(OPENSSL_LIBS)
secdat_SOURCES = \
	main.c \
	cli.c \
	cli.h \
	domain.c \
	domain.h \
	i18n.h \
	store.c \
	store.h
