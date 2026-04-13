AM_CPPFLAGS = \
	-DLOCALEDIR=\"$(localedir)\" \
	-DPACKAGE_NAME=\"$(PACKAGE)\" \
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
