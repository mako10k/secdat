SECDAT_BUILD_ID = $(shell cd $(top_srcdir) >/dev/null 2>&1 && if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then hash=$$(git rev-parse --short=12 HEAD 2>/dev/null || true); if test -n "$$hash"; then if test -n "$$(git status --porcelain --untracked-files=normal 2>/dev/null)"; then printf '%s' "$$hash-dirty"; else printf '%s' "$$hash"; fi; fi; fi)

AM_CPPFLAGS = \
	-DLOCALEDIR=\"$(localedir)\" \
	-DPACKAGE_NAME=\"$(PACKAGE)\" \
	$(OPENSSL_CFLAGS) \
	$(JANSSON_CFLAGS)

BUILT_SOURCES = secdat-build-id.h
CLEANFILES = secdat-build-id.h secdat-build-id.h.tmp
nodist_noinst_HEADERS = secdat-build-id.h

.PHONY: force-secdat-build-id
force-secdat-build-id:

secdat-build-id.h: force-secdat-build-id
	@build_id='$(SECDAT_BUILD_ID)'; \
	{ \
		printf '%s\n' '#ifndef SECDAT_BUILD_ID'; \
		printf '#define SECDAT_BUILD_ID "%s"\n' "$$build_id"; \
		printf '%s\n' '#endif'; \
	} > secdat-build-id.h.tmp; \
	if test -r secdat-build-id.h && cmp -s secdat-build-id.h.tmp secdat-build-id.h; then \
		rm -f secdat-build-id.h.tmp; \
	else \
		mv -f secdat-build-id.h.tmp secdat-build-id.h; \
	fi

include_HEADERS = secdat-sdk.h

lib_LTLIBRARIES = libsecdat.la
libsecdat_la_LDFLAGS = -version-info 1:0:1
EXTRA_libsecdat_la_DEPENDENCIES = Makefile
libsecdat_la_LIBADD = $(OPENSSL_LIBS) $(JANSSON_LIBS)
libsecdat_la_SOURCES = \
	cli.c \
	cli.h \
	domain.c \
	domain.h \
	exec_inject.c \
	exec_inject.h \
	exec_inject_policy_file.c \
	i18n.h \
	json_util.c \
	json_util.h \
	redaction.c \
	redaction.h \
	secdat-sdk.h \
	store.c \
	store.h \
	store_exec_port.h

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
	exec_inject.h \
	i18n.h \
	json_util.h \
	redaction.h \
	secdat-sdk.h \
	store.h \
	store_exec_port.h

main.o cli.lo domain.lo exec_inject.lo redaction.lo store.lo: $(secdat_local_headers)
main.o secdat_fuse-secdat-fuse.o: secdat-build-id.h
