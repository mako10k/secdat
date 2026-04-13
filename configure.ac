AC_PREREQ([2.69])
AC_INIT([secdat], [0.1.0], [noreply@example.invalid])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall])

AC_PROG_CC
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([OPENSSL], [openssl])
AM_GNU_GETTEXT_VERSION([0.21])
AM_GNU_GETTEXT([external])

AC_CONFIG_FILES([
Makefile
src/Makefile
po/Makefile.in
])
AC_OUTPUT
