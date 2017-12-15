PHP_ARG_ENABLE(applepay, for applepay support,
[  --enable-applepay       Enable applepay support])

PHP_ARG_WITH(openssl-dir, for custom OpenSSL dir,
[  --with-openssl-dir[=DIR]  OpenSSL libs and includes directory], no, no)

if test "$PHP_OPENSSL_DIR" != "no"; then
  FOUND_OPENSSL=no
  if test "$PHP_OPENSSL_DIR" = "yes"; then
    PHP_OPENSSL_DIR="/usr/local/openssl /usr/local/ssl /usr/local /usr"
  fi
  for i in $PHP_OPENSSL_DIR; do
    AC_MSG_CHECKING([for OpenSSL at $i])
    if test -r $i/include/openssl/ssl.h; then
      OPENSSL_INCDIR=$i/include
    fi
    if test -r $i/$PHP_LIBDIR/libssl.$SHLIB_SUFFIX_NAME -a -r $i/$PHP_LIBDIR/libcrypto.$SHLIB_SUFFIX_NAME; then
      OPENSSL_LIBDIR=$i/$PHP_LIBDIR
    fi
    test -n "$OPENSSL_INCDIR" && test -n "$OPENSSL_LIBDIR" && FOUND_OPENSSL=yes
    AC_MSG_RESULT([$FOUND_OPENSSL])
    test FOUND_OPENSSL = "yes" && break
  done
  if test "$FOUND_OPENSSL" = "no"; then
    AC_MSG_ERROR([Could not find OpenSSL libs.])
  fi
  AC_MSG_CHECKING([for OpenSSL version])
  AC_EGREP_CPP(yes, [
    #include "$OPENSSL_INCDIR/openssl/opensslv.h"
    #if OPENSSL_VERSION_NUMBER >= 0x10002000L
    yes
    #endif
  ],[
    AC_MSG_RESULT([>= 1.0.2])
  ],[
    AC_MSG_RESULT([< 1.0.2])
    AC_MSG_ERROR([OpenSSL version >= 1.0.2 required.])
  ])
  PHP_ADD_INCLUDE($OPENSSL_INCDIR)
  PHP_ADD_LIBRARY_WITH_PATH(ssl, $OPENSSL_LIBDIR, APPLEPAY_SHARED_LIBADD)
  PHP_ADD_LIBRARY_WITH_PATH(crypto, $OPENSSL_LIBDIR, APPLEPAY_SHARED_LIBADD)
fi

if test "$PHP_APPLEPAY" != "no"; then
  PHP_NEW_EXTENSION(applepay, applepay.c, $ext_shared)
  PHP_SUBST(APPLEPAY_SHARED_LIBADD)
fi   
