AC_PREREQ([2.69])
AC_INIT([secdat], [0.4.0], [noreply@example.invalid])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall])

AC_PROG_CC
AM_PROG_AR
LT_INIT
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([OPENSSL], [openssl])
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.7])

AC_ARG_ENABLE(
    [fuse],
    [AS_HELP_STRING([--enable-fuse], [build the optional secdat-fuse mount helper])],
    [],
    [enable_fuse=no]
)
AS_IF(
    [test "x$enable_fuse" = "xyes"],
    [PKG_CHECK_MODULES([FUSE3], [fuse3])]
)
AM_CONDITIONAL([ENABLE_FUSE], [test "x$enable_fuse" = "xyes"])

AM_GNU_GETTEXT_VERSION([0.21])
AM_GNU_GETTEXT([external])

AC_CONFIG_FILES([
Makefile
src/Makefile
po/Makefile.in
libsecdat.pc
])
AC_OUTPUT
