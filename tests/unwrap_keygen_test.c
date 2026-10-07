/* unwrap_keygen_test.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * wolfPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 * Contract checks for C_UnwrapKey, key and key-pair generation, and key
 * encapsulation.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <limits.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/unwrap_keygen_test"

/* CK_ULONG lengths above the 32-bit range can only be expressed on LP64. */
#if ULONG_MAX > 0xFFFFFFFFUL
    #define WIDE_CK_ULONG
    #define LEN_ABOVE_WORD32(n) ((CK_ULONG)0xFFFFFFFFUL + 1 + (CK_ULONG)(n))
#endif

#ifdef WIDE_CK_ULONG
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    #define AES_UNWRAP_TEST
#endif

#ifdef AES_UNWRAP_TEST
static CK_KEY_TYPE aesType = CKK_AES;

static CK_RV create_aes_unwrap_key(CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass,         sizeof(secretClass)  },
        { CKA_KEY_TYPE, &aesType,             sizeof(aesType)      },
        { CKA_VALUE,    (void*)aes_cbc_key,   sizeof(aes_cbc_key)  },
        { CKA_ENCRYPT,  &ckTrue,              sizeof(ckTrue)       },
        { CKA_UNWRAP,   &ckTrue,              sizeof(ckTrue)       },
        { CKA_PRIVATE,  &ckFalse,             sizeof(ckFalse)      },
    };

    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), key);
}
#endif

#ifndef NO_RSA
static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
static CK_KEY_TYPE rsaType = CKK_RSA;

static CK_RV create_rsa_unwrap_keys(CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE* pub,
                                    CK_OBJECT_HANDLE* priv)
{
    CK_RV rv;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,           &pubClass,        sizeof(pubClass)         },
        { CKA_KEY_TYPE,        &rsaType,         sizeof(rsaType)          },
        { CKA_ENCRYPT,         &ckTrue,          sizeof(ckTrue)           },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,            &privClass,        sizeof(privClass)         },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_UNWRAP,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
    };

    rv = funcList->C_CreateObject(session, pubTmpl,
                                  sizeof(pubTmpl) / sizeof(*pubTmpl), pub);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, privTmpl,
                                      sizeof(privTmpl) / sizeof(*privTmpl),
                                      priv);
    }
    return rv;
}

/* RSA PKCS#1 v1.5 encrypt a 16-byte secret to make a valid wrapped key. */
static CK_RV rsa_wrap_secret(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub,
                             byte* out, CK_ULONG* outLen)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    byte secret[16];

    XMEMSET(secret, 0x5a, sizeof(secret));
    rv = funcList->C_EncryptInit(session, &mech, pub);
    if (rv == CKR_OK) {
        rv = funcList->C_Encrypt(session, secret, sizeof(secret), out, outLen);
    }
    return rv;
}
#endif

static void test_unwrap_wrapped_len_beyond_word32(CK_SESSION_HANDLE session)
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
#ifdef AES_UNWRAP_TEST
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_MECHANISM aesMech = { CKM_AES_CBC_PAD, (void*)aes_cbc_iv,
                             sizeof(aes_cbc_iv) };
    byte aesWrapped[32];
#endif
#ifndef NO_RSA
    CK_OBJECT_HANDLE rsaPub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsaPriv = CK_INVALID_HANDLE;
    CK_MECHANISM rsaMech = { CKM_RSA_PKCS, NULL, 0 };
    byte rsaWrapped[256];
    CK_ULONG rsaWrappedLen = sizeof(rsaWrapped);
#endif

#ifdef AES_UNWRAP_TEST
    XMEMSET(aesWrapped, 0, sizeof(aesWrapped));
    rv = create_aes_unwrap_key(session, &aesKey);
    CHECK_RV(rv, "create AES unwrapping key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &aesMech, aesKey, aesWrapped,
                 LEN_ABOVE_WORD32(sizeof(aesWrapped)), tmpl, tmplCnt, &key);
        CHECK_RV(rv, "AES unwrap with wrapped length beyond 32 bits",
                 CKR_WRAPPED_KEY_LEN_RANGE);
        if (rv == CKR_OK) {
            funcList->C_DestroyObject(session, key);
        }
        key = CK_INVALID_HANDLE;
    }
#endif

#ifndef NO_RSA
    rv = create_rsa_unwrap_keys(session, &rsaPub, &rsaPriv);
    CHECK_RV(rv, "create RSA unwrapping keys", CKR_OK);
    if (rv == CKR_OK) {
        rv = rsa_wrap_secret(session, rsaPub, rsaWrapped, &rsaWrappedLen);
        CHECK_RV(rv, "RSA wrap secret", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &rsaMech, rsaPriv, rsaWrapped,
                 LEN_ABOVE_WORD32(rsaWrappedLen), tmpl, tmplCnt, &key);
        CHECK_RV(rv, "RSA unwrap with wrapped length beyond 32 bits",
                 CKR_WRAPPED_KEY_LEN_RANGE);
        if (rv == CKR_OK) {
            funcList->C_DestroyObject(session, key);
        }
        key = CK_INVALID_HANDLE;

        rv = funcList->C_UnwrapKey(session, &rsaMech, rsaPriv, rsaWrapped,
                 rsaWrappedLen, tmpl, tmplCnt, &key);
        CHECK_RV(rv, "RSA unwrap with exact wrapped length", CKR_OK);
        if (rv == CKR_OK) {
            funcList->C_DestroyObject(session, key);
        }
    }
#endif
    (void)session;
    (void)rv;
    (void)key;
    (void)tmplCnt;
}
#endif /* WIDE_CK_ULONG */

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv == CKR_OK) {
#ifdef WIDE_CK_ULONG
        test_unwrap_wrapped_len_beyond_word32(session);
#endif
        funcList->C_CloseSession(session);
    }
    funcList->C_Finalize(NULL);

    pkcs11_unload();
    return 0;
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 unwrap and key generation contract test ===\n");
    run_test();
    return pkcs11_test_summary();
}
