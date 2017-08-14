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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_applepay.h"

#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/opensslv.h>

ZEND_DECLARE_MODULE_GLOBALS(applepay)

ZEND_BEGIN_ARG_INFO_EX(arginfo_applepay_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_applepay_verify_and_decrypt, 0, 0, 9)
    ZEND_ARG_INFO(0, cryptogram)
    ZEND_ARG_INFO(0, merch_pubkey_path)
    ZEND_ARG_INFO(0, merch_privkey_b64)
    ZEND_ARG_INFO(0, merch_privkey_pass)
    ZEND_ARG_INFO(0, merch_cert_path)
    ZEND_ARG_INFO(0, int_cert_path)
    ZEND_ARG_INFO(0, root_cert_path)
    ZEND_ARG_INFO(0, max_time_diff)
    ZEND_ARG_INFO(0, transaction_time)
ZEND_END_ARG_INFO()

/* {{{ applepay_functions[]
 *
 * Every user visible function must have an entry in applepay_functions[].
 */
const zend_function_entry applepay_functions[] = {
    PHP_FE(applepay_verify_and_decrypt,   arginfo_applepay_verify_and_decrypt)
    PHP_FE(applepay_last_error,           arginfo_applepay_none)
#ifdef PHP_FE_END
    PHP_FE_END    /* Must be the last line in applepay_functions[] */
#else
    {NULL, NULL, NULL}
#endif
};
/* }}} */

/* {{{ applepay_module_entry
 */
zend_module_entry applepay_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    "applepay",
    applepay_functions,
    PHP_MINIT(applepay),
    PHP_MSHUTDOWN(applepay),
    NULL,
    NULL,
    PHP_MINFO(applepay),
#if ZEND_MODULE_API_NO >= 20010901
    PHP_APPLEPAY_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_APPLEPAY
ZEND_GET_MODULE(applepay)
#endif

/* {{{
 * Initialize module globals */
static void _applepay_init_globals(zend_applepay_globals *g)
{
    memset(g, 0, sizeof(zend_applepay_globals));
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(applepay)
{
    int strlen_adjust;

    /** Init globals */
    ZEND_INIT_MODULE_GLOBALS(applepay, _applepay_init_globals, NULL);


#if PHP_MAJOR_VERSION >= 7
    strlen_adjust = 1;
#else
    strlen_adjust = 0;
#endif

    /** Register constants */
    #define APPLEPAY_CONST_EXPAND(c) \
        zend_register_long_constant(#c, sizeof(#c)-strlen_adjust, c, CONST_CS | CONST_PERSISTENT, module_number TSRMLS_CC);
    #include "constants.h"
    #undef APPLEPAY_CONST_EXPAND

    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(applepay)
{
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(applepay)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "applepay support", "enabled");
    php_info_print_table_header(2, "extension version", PHP_APPLEPAY_VERSION);
    php_info_print_table_header(2, "OpenSSL version", SSLeay_version(SSLEAY_VERSION));
    php_info_print_table_end();
}
/* }}} */

// All shared state for applepay_verify_and_decrypt and friends
#define APPLEPAY_TYPE_ECC 0
#define APPLEPAY_TYPE_RSA 1
typedef struct {
    unsigned char *ciphertext;
    size_t         ciphertext_len;
    unsigned char *pubkey_hash;
    size_t         pubkey_hash_len;
    unsigned char *ephemeral_pubkey_text;
    size_t         ephemeral_pubkey_text_len;
    unsigned char *wrapped_key_text;
    size_t         wrapped_key_text_len;
    unsigned char *transaction_id;
    size_t         transaction_id_len;
    unsigned char *secret;
    size_t         secret_len;
    unsigned char *sym_key;
    size_t         sym_key_len;
    EVP_PKEY *merch_pubkey;
    EVP_PKEY *merch_privkey;
    EVP_PKEY *ephemeral_pubkey;
    X509 *merch_cert;
    X509 *int_cert;
    X509 *root_cert;
    X509 *leaf_cert;
    PKCS7 *leaf_p7;
    STACK_OF(X509) *leaf_chain;
    int type; // APPLEPAY_TYPE_*
} applepay_state_t;

// General base64_decode func
static int _applepay_b64_decode(char *b64, int b64_len, unsigned char **data, size_t *data_len) {
    int data_len_int;
    BIO *bio_64 = BIO_new(BIO_f_base64());
    BIO *bio_mem = BIO_new(BIO_s_mem());

    *data = emalloc(b64_len); // data_len will be less than b64_len
    *data_len = 0;

    BIO_set_flags(bio_64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio_mem, b64, b64_len);
    bio_mem = BIO_push(bio_64, bio_mem);
    if ((data_len_int = BIO_read(bio_mem, *data, b64_len)) < 0) {
        efree(*data);
        return APPLEPAY_ERROR;
    }
    *data_len = data_len_int;

    (*data)[*data_len] = 0;
    BIO_free_all(bio_64);

    return APPLEPAY_OK;
}

// Convert ascii hex string to binary
int _applepay_hex_string_to_binary(char *arg, unsigned char **ret, size_t *ret_len) {
    BIGNUM *a = NULL;

    if (BN_hex2bn(&a, arg) == 0) {
        return APPLEPAY_ERROR;
    }

    *ret_len = BN_num_bytes(a);
    *ret = emalloc(*ret_len + 1);

    BN_bn2bin(a, *ret);
    BN_free(a);

    (*ret)[*ret_len] = '\0';

    return APPLEPAY_OK;
}

// Return 1 if `issuer_name` has value at `nid` equal to `val`. Else return 0.
static int _applepay_nid_equals(X509_NAME *issuer_name, int nid, const char *val) {
    #define APPLEPAY_MAX_OBJ_LEN 64
    int rc;
    char buf[APPLEPAY_MAX_OBJ_LEN + 1];
    int val_len;

    memset(buf, 0, APPLEPAY_MAX_OBJ_LEN + 1);
    val_len = strlen(val);

    if (val_len > APPLEPAY_MAX_OBJ_LEN) {
        // This would only happen if someone called _applepay_nid_equals with
        // `val` larger than APPLEPAY_MAX_OBJ_LEN
        return 0;
    } else if (X509_NAME_get_text_by_NID(issuer_name, nid, (char*)buf, APPLEPAY_MAX_OBJ_LEN) != val_len) {
        // Not found (< 0), or length does not match
        return 0;
    } else if (0 != strncmp(val, buf, val_len)) {
        // Not equal
        return 0;
    }

    #undef APPLEPAY_MAX_OBJ_LEN
    return 1;
}

// Return 1 if cert is issued by Apple. Else return 0.
static int _applepay_ensure_cert_issued_by_apple(X509 *cert, const char *common_name) {
    X509_NAME *issuer_name = X509_get_issuer_name(cert);
    if (_applepay_nid_equals(issuer_name, NID_commonName, common_name)
        && _applepay_nid_equals(issuer_name, NID_organizationalUnitName, "Apple Certification Authority")
        && _applepay_nid_equals(issuer_name, NID_organizationName, "Apple Inc.")
        && _applepay_nid_equals(issuer_name, NID_countryName, "US")
    ) {
        return 1;
    }
    return 0;
}

// Parse signature_b64 into leaf_p7, leaf_chain, and leaf_cert
static int _applepay_read_signature(const char *signature_b64, applepay_state_t *state) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());

    // Read signature_b64
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_puts(mem, signature_b64);
    mem = BIO_push(b64, mem);
    state->leaf_p7 = d2i_PKCS7_bio(mem, NULL);
    BIO_free_all(b64);
    if (!state->leaf_p7) {
        return APPLEPAY_ERROR_COULD_NOT_READ_SIGNATURE;
    }

    // Get leaf chain
    switch (OBJ_obj2nid(state->leaf_p7->type)) {
        case NID_pkcs7_signed:
            state->leaf_chain = state->leaf_p7->d.sign->cert;
            break;
        case NID_pkcs7_signedAndEnveloped:
            state->leaf_chain = state->leaf_p7->d.signed_and_enveloped->cert;
            break;
        default:
            return APPLEPAY_ERROR_UNRECOGNIZED_LEAF_CERT_TYPE;
    }

    // We expect exactly 2 certs in the chain (intermediate + leaf)
    if (!state->leaf_chain) {
        return APPLEPAY_ERROR_LEAF_CHAIN_NULL;
    } else if (sk_X509_num(state->leaf_chain) < 1) {
        return APPLEPAY_ERROR_LEAF_CHAIN_SIZE_EQ0;
    } else if (sk_X509_num(state->leaf_chain) < 2) {
        return APPLEPAY_ERROR_LEAF_CHAIN_SIZE_EQ1;
    } else if (sk_X509_num(state->leaf_chain) > 2) {
        return APPLEPAY_ERROR_LEAF_CHAIN_SIZE_GT2;
    }

    // Get reference to leaf_cert
    state->leaf_cert = sk_X509_value(state->leaf_chain, 0);

    // Ensure leaf_cert issued by Apple
    if (!_applepay_ensure_cert_issued_by_apple(state->leaf_cert, "Apple Application Integration CA - G3")) {
        return APPLEPAY_ERROR_LEAF_WRONG_ISSUER;
    }

    return APPLEPAY_OK;
}

// PHP 5/7 compat version of zend_hash_find
static int zend_hash_find_compat(HashTable *ht, char *key, int keylen, zval **zret) {
#if PHP_MAJOR_VERSION >= 7
    zend_string *keystr = zend_string_init(key, keylen, 0);
    *zret = zend_hash_find(ht, keystr);
    zend_string_release(keystr);
    return *zret != NULL ? SUCCESS : FAILURE;
#else
    int retval;
    zval **ztmp = NULL;
    retval = zend_hash_find(ht, key, keylen+1, (void**)&ztmp);
    *zret = *ztmp;
    return retval;
#endif
}

// Extract array keys of `z_cryptogram` into `state`
static int _applepay_parse_cryptogram(zval *z_cryptogram, applepay_state_t *state) {
    HashTable *ht_cryptogram = NULL;
    HashTable *ht_header = NULL;
    zval *z_data = NULL;
    zval *z_header = NULL;
    zval *z_signature = NULL;
    zval *z_version = NULL;
    zval *z_ephemeralPublicKey = NULL;
    zval *z_wrappedKey = NULL;
    zval *z_publicKeyHash = NULL;
    zval *z_transactionId = NULL;
#if PHP_MAJOR_VERSION >= 7
    zval z_data_stack;
    zval z_header_stack;
    zval z_signature_stack;
    zval z_version_stack;
    zval z_ephemeralPublicKey_stack;
    zval z_wrappedKey_stack;
    zval z_publicKeyHash_stack;
    zval z_transactionId_stack;
    z_data = &z_data_stack;
    z_header = &z_header_stack;
    z_signature = &z_signature_stack;
    z_version = &z_version_stack;
    z_ephemeralPublicKey = &z_ephemeralPublicKey_stack;
    z_wrappedKey = &z_wrappedKey_stack;
    z_publicKeyHash = &z_publicKeyHash_stack;
    z_transactionId = &z_transactionId_stack;
#endif

    int rc = APPLEPAY_OK;

    do {
        #define APPLEPAY_PARSE_CRYPTOGRAM_STRKEY(HT, KEYNAME, KEYERR) do { \
            if (zend_hash_find_compat(HT, #KEYNAME, sizeof(#KEYNAME)-1, &z_ ## KEYNAME) != SUCCESS) { \
                return KEYERR; \
            } \
            convert_to_string(z_ ## KEYNAME); \
        } while (0)

        // Get cryptogram hash
        ht_cryptogram = HASH_OF(z_cryptogram);

        // Get data, signature, and version keys
        APPLEPAY_PARSE_CRYPTOGRAM_STRKEY(ht_cryptogram, data, APPLEPAY_ERROR_MISSING_DATA_KEY);
        APPLEPAY_PARSE_CRYPTOGRAM_STRKEY(ht_cryptogram, signature, APPLEPAY_ERROR_MISSING_SIGNATURE_KEY);
        APPLEPAY_PARSE_CRYPTOGRAM_STRKEY(ht_cryptogram, version, APPLEPAY_ERROR_MISSING_VERSION_KEY);

        // Ensure correct version
        if (strcmp(Z_STRVAL_P(z_version), "EC_v1") == 0) {
            state->type = APPLEPAY_TYPE_ECC;
        } else if (strcmp(Z_STRVAL_P(z_version), "RSA_v1") == 0) {
            state->type = APPLEPAY_TYPE_RSA;
        } else {
            rc = APPLEPAY_ERROR_WRONG_VERSION;
            break;
        }

        // Get header hash
        if (zend_hash_find_compat(ht_cryptogram, "header", sizeof("header")-1, &z_header) != SUCCESS) {
            rc = APPLEPAY_ERROR_MISSING_HEADER_KEY;
            break;
        }
        convert_to_array(z_header);
        ht_header = HASH_OF(z_header);

        // Get (wrappedKey OR ephemeralPublicKey), publicKeyHash, and transactionId keys
        if (state->type == APPLEPAY_TYPE_ECC) {
            APPLEPAY_PARSE_CRYPTOGRAM_STRKEY(ht_header, ephemeralPublicKey, APPLEPAY_ERROR_MISSING_EPHEMERAL_PUBKEY_KEY);
        } else {
            APPLEPAY_PARSE_CRYPTOGRAM_STRKEY(ht_header, wrappedKey, APPLEPAY_ERROR_MISSING_WRAPPED_KEY);
        }
        APPLEPAY_PARSE_CRYPTOGRAM_STRKEY(ht_header, publicKeyHash, APPLEPAY_ERROR_MISSING_PUBKEY_HASH_KEY);
        APPLEPAY_PARSE_CRYPTOGRAM_STRKEY(ht_header, transactionId, APPLEPAY_ERROR_MISSING_TRANSACTION_ID_KEY);
        #undef APPLEPAY_PARSE_CRYPTOGRAM_STRKEY

        // Base64 decode stuff
        if (_applepay_b64_decode(Z_STRVAL_P(z_data), Z_STRLEN_P(z_data), &state->ciphertext, &state->ciphertext_len) != APPLEPAY_OK) {
            rc = APPLEPAY_ERROR_COULD_NOT_B64DECODE_CIPHERTEXT;
            break;
        }
        if (_applepay_b64_decode(Z_STRVAL_P(z_publicKeyHash), Z_STRLEN_P(z_publicKeyHash), &state->pubkey_hash, &state->pubkey_hash_len) != APPLEPAY_OK) {
            rc = APPLEPAY_ERROR_COULD_NOT_B64DECODE_PUBKEY_HASH;
            break;
        }
        if (state->type == APPLEPAY_TYPE_ECC) {
            if (_applepay_b64_decode(Z_STRVAL_P(z_ephemeralPublicKey), Z_STRLEN_P(z_ephemeralPublicKey), &state->ephemeral_pubkey_text, &state->ephemeral_pubkey_text_len) != APPLEPAY_OK) {
                rc = APPLEPAY_ERROR_COULD_NOT_B64DECODE_EPHEMERAL_PUBKEY;
                break;
            }
        } else {
            if (_applepay_b64_decode(Z_STRVAL_P(z_wrappedKey), Z_STRLEN_P(z_wrappedKey), &state->wrapped_key_text, &state->wrapped_key_text_len) != APPLEPAY_OK) {
                rc = APPLEPAY_ERROR_COULD_NOT_B64DECODE_WRAPPED_KEY;
                break;
            }
        }

        // Hex decode transaction_id_hex
        if (_applepay_hex_string_to_binary(Z_STRVAL_P(z_transactionId), &state->transaction_id, &state->transaction_id_len) != APPLEPAY_OK) {
            rc = APPLEPAY_ERROR_COULD_NOT_HEXDECODE_TRANSACTION_ID;
            break;
        }

        if ((rc = _applepay_read_signature(Z_STRVAL_P(z_signature), state)) != APPLEPAY_OK) {
            break;
        }
    } while (0);

    return rc;
}

// Read an X509 cert from the file system
static int _applepay_read_x509_from_file(char *path, X509 **cert) {
    FILE *fp;

    // Open file
    fp = fopen(path, "rb");
    if (!fp) {
        return APPLEPAY_ERROR; // perror
    }

    // Read cert
    d2i_X509_fp(fp, cert);
    fclose(fp);

    if (!*cert) {
        return APPLEPAY_ERROR; // err_get_error
    }
    return APPLEPAY_OK;
}

// Read merch_pubkey from the file system
static int _applepay_read_merch_pubkey(const char *merch_pubkey_path, applepay_state_t *state) {
    FILE *fp;

    // Open file
    fp = fopen(merch_pubkey_path, "rb");
    if (!fp) {
        return APPLEPAY_ERROR_COULD_NOT_OPEN_MERCH_PUBKEY;
    }

    // Read key
    PEM_read_PUBKEY(fp, &state->merch_pubkey, NULL, NULL);
    fclose(fp);

    if (!state->merch_pubkey) {
        return APPLEPAY_ERROR_COULD_NOT_READ_MERCH_PUBKEY;
    }
    return APPLEPAY_OK;
}

// Read merch_privkey from the file system
static int _applepay_read_merch_privkey(const char *merch_privkey_b64, size_t merch_privkey_b64_len, const char *merch_privkey_pass, applepay_state_t *state) {
    PKCS12 *p12;
    int rc = APPLEPAY_OK;
    BIO *bio_64 = BIO_new(BIO_f_base64());
    BIO *bio_mem = BIO_new(BIO_s_mem());

    // Read merch_privkey_b64 into BIO
    BIO_set_flags(bio_64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio_mem, merch_privkey_b64, merch_privkey_b64_len);
    bio_mem = BIO_push(bio_64, bio_mem);

    // Read key
    p12 = d2i_PKCS12_bio(bio_mem, NULL);
    BIO_free_all(bio_64);
    if (!p12) {
        return APPLEPAY_ERROR_COULD_NOT_READ_MERCH_PRIVKEY;
    }

    // Parse key
    if (PKCS12_parse(p12, merch_privkey_pass, &state->merch_privkey, NULL, NULL) != 1) {
        rc = APPLEPAY_ERROR_COULD_NOT_PARSE_MERCH_PRIVKEY;
    }

    PKCS12_free(p12);
    return rc;
}

// Read ephemeral_pubkey_text as key
static int _applepay_parse_ephemeral_pubkey(applepay_state_t *state) {
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_write(mem, state->ephemeral_pubkey_text, state->ephemeral_pubkey_text_len);
    state->ephemeral_pubkey = d2i_PUBKEY_bio(mem, NULL);
    BIO_free_all(mem);
    if (!state->ephemeral_pubkey) {
        return APPLEPAY_ERROR_COULD_NOT_PARSE_EPHEMERAL_PUBKEY;
    }
    return APPLEPAY_OK;
}

// Return APPLEPAY_OK if oid exists in cert's extensions, else APPLEPAY_ERROR
static int _applepay_check_cert_oid(X509 *cert, const char *oid, X509_EXTENSION **ret_ext) {
    char objbuf[80];
    int i;
    X509_EXTENSION* ext = NULL;
    int extcount = X509_get_ext_count(cert);
    for (i = 0; i < extcount; i++) {
        ext = X509_get_ext(cert, i);
        if ((OBJ_obj2txt(objbuf, sizeof(objbuf), X509_EXTENSION_get_object(ext), 1) > 0) &&
            (strcmp(oid, objbuf) == 0)) {
            if (ret_ext) {
                *ret_ext = ext;
            }
            return APPLEPAY_OK;
        }
    }
    return APPLEPAY_ERROR;
}

// Verify chain of trust from leaf_cert to root_cert
static int _applepay_verify_chain(applepay_state_t *state) {
    X509_STORE *store;
    X509_STORE_CTX *ctx;
    int rc;

    rc = APPLEPAY_OK;
    store = X509_STORE_new(); // These cannot be on the stack as they don't have initializers
    ctx = X509_STORE_CTX_new();

    do {
        // Add root cert to store
        if (!X509_STORE_add_cert(store, state->root_cert)) {
            rc = APPLEPAY_ERROR_COULD_NOT_ADD_ROOT_CERT_TO_STORE;
            break;
        }

        // Verify int signed by root
        if (!X509_STORE_CTX_init(ctx, store, state->int_cert, NULL)) {
            rc = APPLEPAY_ERROR_COULD_NOT_INIT_INT_STORE_CTX;
            break;
        } else if (X509_verify_cert(ctx) != 1) {
            rc = APPLEPAY_ERROR_FAILED_TO_VERIFY_INT_CERT;
            break;
        }

        // Verify leaf signed by root
        X509_STORE_CTX_cleanup(ctx);
        if (!X509_STORE_CTX_init(ctx, store, state->leaf_cert, state->leaf_chain)) {
            rc = APPLEPAY_ERROR_COULD_NOT_INIT_LEAF_STORE_CTX;
            break;
        } else if (X509_verify_cert(ctx) != 1) {
            rc = APPLEPAY_ERROR_FAILED_TO_VERIFY_LEAF_CERT;
            break;
        }
    } while (0);

    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);

    return rc;
}

// Verify that the PKCS7 signed data is actually signed by the leaf certificate
static int _applepay_verify_signature(applepay_state_t *state) {
    BIO *bio;
    X509_STORE *store;
    X509_PUBKEY *leaf_pub_key;
    ASN1_OBJECT *pkalg;
    int rc;
    int message_digest_alg_nid;

    rc = APPLEPAY_OK;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    message_digest_alg_nid = state->leaf_cert ? X509_get_signature_nid(state->leaf_cert) : 0;
#else
    message_digest_alg_nid = (state->leaf_cert && state->leaf_cert->sig_alg && state->leaf_cert->sig_alg->algorithm) ?
        OBJ_obj2nid(state->leaf_cert->sig_alg->algorithm) :
        0;
#endif

    bio = BIO_new(BIO_s_mem());
    store = X509_STORE_new();
    if (!bio || !store) {
        return APPLEPAY_ERROR_OUT_OF_MEM;
    }

    do {
        // Ensure messageDigest algorithm == ECDSA-with-sha256
        // TODO Why is this not NID_sha256WithRSAEncryption for APPLEPAY_TYPE_RSA?
        if (!state->leaf_cert || message_digest_alg_nid != NID_ecdsa_with_SHA256) {
            rc = APPLEPAY_ERROR_LEAF_CERT_WRONG_ALGORITHM;
            break;
        }

        // Ensure correct pub key algorithm
        if (NULL == (leaf_pub_key = X509_get_X509_PUBKEY(state->leaf_cert))) {
            rc = APPLEPAY_ERROR_COULD_NOT_GET_LEAF_PUBKEY;
            break;
        }
        if (1 != X509_PUBKEY_get0_param(&pkalg, NULL, NULL, NULL, leaf_pub_key)) {
            rc = APPLEPAY_ERROR_COULD_NOT_GET_LEAF_PUBKEY_ALGORITHM;
            break;
        }
        if (OBJ_obj2nid(pkalg) != (state->type == APPLEPAY_TYPE_ECC ? NID_X9_62_id_ecPublicKey : NID_rsaEncryption)) {
            rc = APPLEPAY_ERROR_LEAF_CERT_WRONG_PUBKEY_ALGORITHM;
            break;
        }

        // Ensure signature is correct
        if (state->type == APPLEPAY_TYPE_ECC) {
            BIO_write(bio, state->ephemeral_pubkey_text, state->ephemeral_pubkey_text_len);
        } else {
            BIO_write(bio, state->wrapped_key_text, state->wrapped_key_text_len);
        }
        BIO_write(bio, state->ciphertext, state->ciphertext_len);
        BIO_write(bio, state->transaction_id, state->transaction_id_len);

        if (!X509_STORE_add_cert(store, state->root_cert)) {
            rc = APPLEPAY_ERROR_COULD_NOT_ADD_ROOT_CERT_TO_STORE;
            break;
        }

        if (!X509_STORE_add_cert(store, state->int_cert)) {
            rc = APPLEPAY_ERROR_COULD_NOT_ADD_INT_CERT_TO_STORE;
            break;
        }

        if (PKCS7_verify(state->leaf_p7, NULL, store, bio, NULL, PKCS7_NOCHAIN) != 1) {
            rc = APPLEPAY_ERROR_SIGNATURE_NOT_VERIFIED;
            break;
        }
    } while (0);

    BIO_free_all(bio);
    X509_STORE_free(store);
    return rc;
}

// Verify signing time of certs in leaf chain
static int _applepay_check_signing_time(applepay_state_t *state, time_t txn_time, time_t max_time_diff) {
    int i;
    int sic;
    STACK_OF(PKCS7_SIGNER_INFO)* sk;

    // Get signer infos
    sk = PKCS7_get_signer_info(state->leaf_p7);
    if ((sic = sk_PKCS7_SIGNER_INFO_num(sk)) < 1) {
        return APPLEPAY_ERROR_LEAF_SIGNER_INFO_MISSING;
    }


    // Check signer infos
    for (i = 0; i < sic; i++) {
        ASN1_UTCTIME *utctime;
        ASN1_TYPE *so;
        PKCS7_SIGNER_INFO* si;

        si = sk_PKCS7_SIGNER_INFO_value(sk, i);
        so = PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime);
        if (so->type == V_ASN1_UTCTIME) {
            utctime = so->value.utctime;
        } else {
            return APPLEPAY_ERROR_LEAF_SIGNING_TIME_IS_INVALID;
        }

        if (ASN1_UTCTIME_check(utctime) < 1) {
            return APPLEPAY_ERROR_LEAF_SIGNING_TIME_IS_INVALID;
        }
        if (ASN1_UTCTIME_cmp_time_t(utctime, txn_time + max_time_diff) >= 1) {
            return APPLEPAY_ERROR_LEAF_SIGNING_TIME_IN_FUTURE;
        } else if (ASN1_UTCTIME_cmp_time_t(utctime, txn_time - max_time_diff) < 0) {
            return APPLEPAY_ERROR_LEAF_SIGNING_TIME_TOO_OLD;
        }
    }

    return APPLEPAY_OK;
}

// Verify pubkey_hash matches cert digest
static int _applepay_verify_pubkey_hash(applepay_state_t *state) {
    unsigned char cert_digest[SHA256_DIGEST_LENGTH];
    unsigned char *merch_cert_pubkey, *merch_cert_pubkey_cur;
    int merch_cert_pubkey_len;
    SHA256_CTX sha256;

    // Get sha256 digest of merch_cert.pubkey
    merch_cert_pubkey_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(state->merch_cert), NULL);
    merch_cert_pubkey = emalloc(merch_cert_pubkey_len);
    merch_cert_pubkey_cur = merch_cert_pubkey;
    i2d_X509_PUBKEY(X509_get_X509_PUBKEY(state->merch_cert), &merch_cert_pubkey_cur);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, merch_cert_pubkey, merch_cert_pubkey_len);
    SHA256_Final(cert_digest, &sha256);
    efree(merch_cert_pubkey);

    // Compare digest to pubkey_hash
    if (state->pubkey_hash_len != SHA256_DIGEST_LENGTH
        || memcmp(cert_digest, state->pubkey_hash, SHA256_DIGEST_LENGTH) != 0
    ) {
        return APPLEPAY_ERROR_FAILED_TO_VERIFY_PUBKEY_HASH;
    }

    return APPLEPAY_OK;
}

// Generate shared secret
static int _applepay_generate_secret(applepay_state_t *state) {
    EVP_PKEY_CTX *ctx;

    // Create the context for the shared secret derivation
    if (NULL == (ctx = EVP_PKEY_CTX_new(state->merch_privkey, NULL)))
        return APPLEPAY_ERROR_COULD_NOT_CREATE_SECRET_CTX;

    // Initialize
    if (1 != EVP_PKEY_derive_init(ctx))
        return APPLEPAY_ERROR_COULD_NOT_INIT_SECRET_CTX;

    // Provide the peer public key
    if (1 != EVP_PKEY_derive_set_peer(ctx, state->ephemeral_pubkey))
        return APPLEPAY_ERROR_COULD_NOT_SET_SECRET_CTX_PEERKEY;

    // Determine buffer length for shared secret
    if (1 != EVP_PKEY_derive(ctx, NULL, &state->secret_len))
        return APPLEPAY_ERROR_COULD_NOT_DERIVE_BUFLEN;

    // Create the buffer
    if (NULL == (state->secret = emalloc(state->secret_len)))
        return APPLEPAY_ERROR_COULD_NOT_CREATE_SECRET_BUF;

    // Derive the shared secret
    if (1 != (EVP_PKEY_derive(ctx, state->secret, &state->secret_len)))
        return APPLEPAY_ERROR_COULD_NOT_DERIVE_SECRET;

    EVP_PKEY_CTX_free(ctx);

    return APPLEPAY_OK;
}

// Decrypt symmetric key from wrappedKey
static int _applepay_decrypt_symkey(applepay_state_t *state) {
    EVP_PKEY_CTX *ctx;

    // Create the context for the shared secret derivation
    if (NULL == (ctx = EVP_PKEY_CTX_new(state->merch_privkey, NULL)))
        return APPLEPAY_ERROR_COULD_NOT_CREATE_DECRYPT_CTX;

    // Initialize
    if (1 != EVP_PKEY_decrypt_init(ctx))
        return APPLEPAY_ERROR_COULD_NOT_INIT_DECRYPT_CTX;

    // Set 'RSA/ECB/OAEPWithSHA256AndMGF1Padding' alg
    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING))
        return APPLEPAY_ERROR_COULD_NOT_CONFIG_DECRYPT_CTX;
    if (1 != EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()))
        return APPLEPAY_ERROR_COULD_NOT_CONFIG_DECRYPT_CTX;
    if (1 != EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()))
        return APPLEPAY_ERROR_COULD_NOT_CONFIG_DECRYPT_CTX;

    // Get sym_key_len
    if (1 != EVP_PKEY_decrypt(ctx, NULL, &state->sym_key_len, state->wrapped_key_text, state->wrapped_key_text_len))
        return APPLEPAY_ERROR_COULD_NOT_GET_SYMKEY_LEN;

    // Allocate sym_key
    if (NULL == (state->sym_key = emalloc(state->sym_key_len)))
        return APPLEPAY_ERROR_COULD_NOT_ALLOCATE_SYMKEY;

    // Actually decrypt
    if (1 != EVP_PKEY_decrypt(ctx, state->sym_key, &state->sym_key_len, state->wrapped_key_text, state->wrapped_key_text_len))
        return APPLEPAY_ERROR_COULD_NOT_DECRYPT_WRAPPED_KEY;

    EVP_PKEY_CTX_free(ctx);

    return APPLEPAY_OK;
}

// Read merchid from merch_cert
static int _applepay_read_merchid(applepay_state_t *state, unsigned char **merchid, size_t *merchid_len) {
    BIGNUM *a = NULL;
    X509_EXTENSION *ext = NULL;
    size_t bytes;

    // Get merchid ext
    _applepay_check_cert_oid(state->merch_cert, "1.2.840.113635.100.6.32", &ext);
    if (!ext) {
        return APPLEPAY_ERROR_MERCH_CERT_MISSING_MERCHID;
    }

    // Convert to bytes (shave of 2-char prefix and get hex)
    if (ext->value->length <= 2) {
        return APPLEPAY_ERROR_MERCHID_TOO_SHORT;
    }

    if (BN_hex2bn(&a, (char *)(ext->value->data + 2)) == 0) {
        BN_free(a);
        return APPLEPAY_ERROR_FAILED_TO_PARSE_MERCHID;
    }
    *merchid_len = BN_num_bytes(a);
    *merchid = emalloc(*merchid_len);
    BN_bn2bin(a, *merchid);
    BN_free(a);

    return APPLEPAY_OK;
}

// Generate symmetric key
static int _applepay_generate_symkey(applepay_state_t *state) {
    SHA256_CTX sha256;
    char oinfo[128];
    unsigned char *merchid;
    size_t oinfo_len, merchid_len;
    int rc;

    if ((rc = _applepay_read_merchid(state, &merchid, &merchid_len)) != APPLEPAY_OK) {
         return rc;
    }

    if (NULL == (state->sym_key = emalloc(SHA256_DIGEST_LENGTH))) {
        return APPLEPAY_ERROR_COULD_NOT_ALLOCATE_SYMKEY;
    }
    state->sym_key_len = SHA256_DIGEST_LENGTH;

    oinfo_len = snprintf(oinfo, 128, "%c%sApple", 0x0d, "id-aes256-GCM");

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, "\x00\x00\x00\x01", 4);
    SHA256_Update(&sha256, state->secret, state->secret_len);
    SHA256_Update(&sha256, (char*)oinfo, oinfo_len);
    SHA256_Update(&sha256, (char*)merchid, merchid_len);
    SHA256_Final(state->sym_key, &sha256);

    efree(merchid);

    return APPLEPAY_OK;
}

// Decrypt ciphertext using sym_key
static int _applepay_decrypt_ciphertext(applepay_state_t *state, char **decrypted, int *decrypted_len) {
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher;
    unsigned char init_vector[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    unsigned char *decrypted_cur = NULL;
    int outlen;
    int rc;

    EVP_CIPHER_CTX_init(&ctx);

    rc = APPLEPAY_OK;
    do {
        // Select cipher
        if (state->type == APPLEPAY_TYPE_ECC) {
            cipher = EVP_aes_256_gcm();
        } else {
            cipher = EVP_aes_128_gcm();
        }
        if (EVP_DecryptInit(&ctx, cipher, NULL, NULL) != 1) {
            rc = APPLEPAY_ERROR_FAILED_TO_INIT_DECRYPT;
            break;
        }

        // Set IV length, omit for 96 bits
        EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(init_vector), NULL);

        // Specify key and IV
        if (EVP_DecryptInit(&ctx, NULL, state->sym_key, init_vector) != 1) {
            rc = APPLEPAY_ERROR_FAILED_TO_INIT_DECRYPT;
            break;
        }

        // Alloc space for decrypted payload
        *decrypted = emalloc(state->ciphertext_len + EVP_CIPHER_CTX_block_size(&ctx) + 1);
        decrypted_cur = *decrypted;
        *decrypted_len = 0;

        // Decrypt plaintext
        // Cipher text is suffixed by 16 bytes of tag. So don't pass it in
        if (state->ciphertext_len <= 16) {
            rc = APPLEPAY_ERROR_INVALID_INPUT_CIPHERTEXT_TOO_SHORT;
            break;
        }
        if (EVP_DecryptUpdate(&ctx, decrypted_cur, &outlen, state->ciphertext, state->ciphertext_len - 16) != 1) {
            rc = APPLEPAY_ERROR_FAILED_TO_UPDATE_DECRYPT;
            break;
        }
        *decrypted_len += outlen;

        // Set expected tag value
        EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, 16, state->ciphertext + state->ciphertext_len - 16);

        // Finalize: note get no output for GCM
        if (EVP_DecryptFinal_ex(&ctx, decrypted_cur, &outlen) != 1) {
            rc = APPLEPAY_ERROR_FAILED_TO_DECRYPT;
            break;
        }
        *decrypted_len += outlen;

        // Null terminate
        (*decrypted)[*decrypted_len] = 0;
    } while (0);

    EVP_CIPHER_CTX_cleanup(&ctx);

    return rc;
}

static void _applepay_cleanup_state(applepay_state_t *state) {
    if (state->ciphertext) efree(state->ciphertext);
    if (state->pubkey_hash) efree(state->pubkey_hash);
    if (state->ephemeral_pubkey_text) efree(state->ephemeral_pubkey_text);
    if (state->wrapped_key_text) efree(state->wrapped_key_text);
    if (state->transaction_id) efree(state->transaction_id);
    if (state->secret) {
        OPENSSL_cleanse(state->secret, state->secret_len);
        efree(state->secret);
    }
    if (state->sym_key) {
        OPENSSL_cleanse(state->sym_key, state->sym_key_len);
        efree(state->sym_key);
    }

    if (state->merch_pubkey) EVP_PKEY_free(state->merch_pubkey);
    if (state->merch_privkey) EVP_PKEY_free(state->merch_privkey);
    if (state->ephemeral_pubkey) EVP_PKEY_free(state->ephemeral_pubkey);

    if (state->merch_cert) X509_free(state->merch_cert);
    if (state->int_cert) X509_free(state->int_cert);
    if (state->root_cert) X509_free(state->root_cert);

    // Freeing leaf_p7 should free leaf_cert, leaf_chain, and message_digest
    if (state->leaf_p7) PKCS7_free(state->leaf_p7);
}

/* {{{ proto mixed applepay_verify_and_decrypt(array cryptogram,
           string pubkey_path, string privkey_path, string privkey_pass,
           string merch_cert_path, string int_cert_path,
           string root_cert_path, int max_time_diff, int txn_time)
   Verifies and decrypts an Apple Pay cryptogram. Returns FALSE if unable to
   verify or decrypt, and sets error code retrievable by
   applepay_last_error(). Otherwise, the decrypted payload is returned as
   a string. */
PHP_FUNCTION(applepay_verify_and_decrypt)
{
    int rc = APPLEPAY_OK;
    zval *z_cryptogram = NULL;
    char *decrypted = NULL;
    int  decrypted_len = 0;
    applepay_state_t state;
    char *merch_pubkey_path, *merch_privkey_b64, *merch_privkey_pass, *merch_cert_path, *int_cert_path, *root_cert_path;
    size_t merch_pubkey_path_len, merch_privkey_b64_len, merch_privkey_pass_len, merch_cert_path_len, int_cert_path_len, root_cert_path_len;
    long long max_time_diff, transaction_time;

    // Zero out state
    memset(&state, 0, sizeof(applepay_state_t));

    // Parse params
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "apsppppll",
        &z_cryptogram, &merch_pubkey_path, &merch_pubkey_path_len,
        &merch_privkey_b64, &merch_privkey_b64_len,
        &merch_privkey_pass, &merch_privkey_pass_len,
        &merch_cert_path, &merch_cert_path_len,
        &int_cert_path, &int_cert_path_len,
        &root_cert_path, &root_cert_path_len,
        &max_time_diff, &transaction_time
    ) == FAILURE) {
        return;
    }

    // Perform steps outlined in http://goo.gl/jmkWSF
    do {
        if ((max_time_diff < 0) || (max_time_diff >= INT16_MAX) ||
            (transaction_time < 0) || (transaction_time >= INT32_MAX) ||
            ((transaction_time + max_time_diff) >= INT32_MAX)) {
            rc = APPLEPAY_ERROR_INVALID_INPUT_TIME;
            break;
        }
        if ((rc = _applepay_parse_cryptogram(z_cryptogram, &state)) != APPLEPAY_OK) {
            break;
        }
        if ((rc = _applepay_read_x509_from_file(merch_cert_path, &state.merch_cert)) != APPLEPAY_OK) {
            rc = APPLEPAY_ERROR_COULD_NOT_READ_MERCH_CERT;
            break;
        }
        if ((rc = _applepay_read_x509_from_file(int_cert_path, &state.int_cert)) != APPLEPAY_OK) {
            rc = APPLEPAY_ERROR_COULD_NOT_READ_INT_CERT;
            break;
        }
        if ((rc = _applepay_read_x509_from_file(root_cert_path, &state.root_cert)) != APPLEPAY_OK) {
            rc = APPLEPAY_ERROR_COULD_NOT_READ_ROOT_CERT;
            break;
        }
        if (!_applepay_ensure_cert_issued_by_apple(state.root_cert, "Apple Root CA - G3")) {
            rc = APPLEPAY_ERROR_ROOT_WRONG_ISSUER;
            break;
        }
        if ((rc = _applepay_read_merch_pubkey(merch_pubkey_path, &state)) != APPLEPAY_OK) {
            break;
        }
        if ((rc = _applepay_read_merch_privkey(merch_privkey_b64, merch_privkey_b64_len, merch_privkey_pass, &state)) != APPLEPAY_OK) {
            break;
        }
        if (state.type == APPLEPAY_TYPE_ECC) {
            if ((rc = _applepay_parse_ephemeral_pubkey(&state)) != APPLEPAY_OK) {
                break;
            }
        }
        if ((rc = _applepay_check_cert_oid(state.leaf_cert, "1.2.840.113635.100.6.29", NULL)) != APPLEPAY_OK) { // Step 1a
            rc = APPLEPAY_ERROR_LEAF_CERT_MISSING_OID;
            break;
        }
        if ((rc = _applepay_check_cert_oid(state.int_cert, "1.2.840.113635.100.6.2.14", NULL)) != APPLEPAY_OK) { // Step 1a
            rc = APPLEPAY_ERROR_INT_CERT_MISSING_OID;
            break;
        }
        if ((rc = _applepay_verify_chain(&state)) != APPLEPAY_OK) { // Step 1c
            break;
        }
        if ((rc = _applepay_verify_signature(&state)) != APPLEPAY_OK) { // Step 1d
            break;
        }
        if ((rc = _applepay_check_signing_time(&state, transaction_time, max_time_diff)) != APPLEPAY_OK) { // Step 1e
            break;
        }
        if ((rc = _applepay_verify_pubkey_hash(&state)) != APPLEPAY_OK) { // Step 2
            break;
        }
        if (state.type == APPLEPAY_TYPE_ECC) {
            if ((rc = _applepay_generate_secret(&state)) != APPLEPAY_OK) { // Step 3
                break;
            }
            if ((rc = _applepay_generate_symkey(&state)) != APPLEPAY_OK) { // Step 3
                break;
            }
        } else {
            if ((rc = _applepay_decrypt_symkey(&state)) != APPLEPAY_OK) { // Step 3
                break;
            }
        }
        if ((rc = _applepay_decrypt_ciphertext(&state, &decrypted, &decrypted_len)) != APPLEPAY_OK) { // Step 4
            break;
        }
    } while (0);

    // Clean up
    _applepay_cleanup_state(&state);

    // Return FALSE on error
    if (rc != APPLEPAY_OK || !decrypted) {
        if (decrypted) efree(decrypted);
        APPLEPAY_G(last_error) = rc;
        RETURN_FALSE;
    }

    // TODO Eat japanese curry with klee

    // Return decrypted payload
#if PHP_MAJOR_VERSION >= 7
    RETVAL_STRINGL(decrypted, decrypted_len);
    efree(decrypted);
#else
    // `decrypted` was emalloc'd in _applepay_decrypt_ciphertext so no need to copy
    RETURN_STRINGL(decrypted, decrypted_len, 0);
#endif
}

/* {{{ proto int applepay_last_error(void)
   Returns the last error code. */
PHP_FUNCTION(applepay_last_error)
{
    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }
    RETURN_LONG(APPLEPAY_G(last_error));
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
