SECDAT_BUILD_ID = $(shell cd $(top_srcdir) >/dev/null 2>&1 && if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then hash=$$(git rev-parse --short=12 HEAD 2>/dev/null || true); if test -n "$$hash"; then if test -n "$$(git status --porcelain --untracked-files=normal 2>/dev/null)"; then printf '%s' "$$hash-dirty"; else printf '%s' "$$hash"; fi; fi; fi)

AM_CPPFLAGS = \
	-DLOCALEDIR=\"$(localedir)\" \
	-DPACKAGE_NAME=\"$(PACKAGE)\" \
	-DSECDAT_BUILD_ID=\"$(SECDAT_BUILD_ID)\" \
	$(OPENSSL_CFLAGS)

include_HEADERS = secdat-sdk.h

lib_LTLIBRARIES = libsecdat.la
libsecdat_la_LDFLAGS = -version-info 0:0:0
libsecdat_la_LIBADD = $(OPENSSL_LIBS)
libsecdat_la_SOURCES = \
	cli.c \
	cli.h \
	domain.c \
	domain.h \
	i18n.h \
	secdat-sdk.h \
	store.c \
	store.h

bin_PROGRAMS = secdat
secdat_LDADD = libsecdat.la
secdat_SOURCES = \
	main.c \
	i18n.h

if ENABLE_FUSE
bin_PROGRAMS += secdat-fuse
secdat_fuse_CPPFLAGS = $(AM_CPPFLAGS) $(FUSE3_CFLAGS)
secdat_fuse_LDADD = libsecdat.la $(FUSE3_LIBS)
secdat_fuse_SOURCES = \
	secdat-fuse.c \
	domain.h \
	i18n.h \
	secdat-sdk.h
endif

secdat_local_headers = \
	cli.h \
	domain.h \
	i18n.h \
	secdat-sdk.h \
	store.h

main.o cli.lo domain.lo store.lo: $(secdat_local_headers)
