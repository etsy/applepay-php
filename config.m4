PHP_ARG_WITH(applepay, for applepay support,
[  --with-applepay             Include applepay support])

if test "$PHP_APPLEPAY" != "no"; then
  PHP_NEW_EXTENSION(applepay, applepay.c, $ext_shared)
fi   
