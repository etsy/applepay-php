/*
  +----------------------------------------------------------------------+
  | applepay                                                             |
  +----------------------------------------------------------------------+
  | This source file is subject to the MIT license that is bundled with  |
  | this package in the file LICENSE, and is available through the       |
  | world-wide-web at the following url:                                 |
  | http://opensource.org/licenses/mit-license.php                       |
  +----------------------------------------------------------------------+
  | Authors: Adam Saponara <as@etsy.com>                                 |
  |          Stephen Buckley <sbuckley@etsy.com>                         |
  |          Keyur Govande <keyur@etsy.com>                              |
  |          Rasmus Lerdorf <rasmus@etsy.com>                            |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_APPLEPAY_H
#define PHP_APPLEPAY_H

extern zend_module_entry applepay_module_entry;
#define phpext_applepay_ptr &applepay_module_entry

#ifdef PHP_WIN32
#    define PHP_APPLEPAY_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#    define PHP_APPLEPAY_API __attribute__ ((visibility("default")))
#else
#    define PHP_APPLEPAY_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#define PHP_APPLEPAY_VERSION "0.2.1"

typedef enum {
    #define APPLEPAY_CONST_EXPAND(c) c,
    #include "constants.h"
    #undef APPLEPAY_CONST_EXPAND
    APPLEPAY_UNUSED
} applepay_error_codes_enum;

ZEND_BEGIN_MODULE_GLOBALS(applepay)
int last_error;
ZEND_END_MODULE_GLOBALS(applepay)

PHP_MINIT_FUNCTION(applepay);
PHP_MSHUTDOWN_FUNCTION(applepay);
PHP_MINFO_FUNCTION(applepay);

PHP_FUNCTION(applepay_verify_and_decrypt);
PHP_FUNCTION(applepay_last_error);

#ifdef ZTS
#define APPLEPAY_G(v) TSRMG(applepay_globals_id, zend_applepay_globals *, v)
#else
#define APPLEPAY_G(v) (applepay_globals.v)
#endif

#endif    /* PHP_APPLEPAY_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
