AC_INIT([HsOpenSSL], [], [phonohawk@ps.sakura.ne.jp])

AC_CONFIG_SRCDIR([OpenSSL/SSL.hsc])

PKG_CHECK_MODULES(
        [OPENSSL], [openssl >= 0.9.7l], [],
        [AC_MSG_ERROR([openssl >= 0.9.7l is required to build this package.])])

AC_CONFIG_FILES([
        HsOpenSSL.buildinfo
])
AC_OUTPUT