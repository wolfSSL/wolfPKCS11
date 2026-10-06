/* attribute_validation_test.c
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
 * Attribute templates supplied when creating or updating objects are
 * validated, and defaulted attributes behave as PKCS#11 specifies.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <string.h>

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

#define TEST_DIR "./store/attribute_validation_test"

#if defined(WOLFPKCS11_KEYPAIR_GEN_COMMON_LABEL) && \
    defined(HAVE_AES_KEYWRAP) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(NO_RSA) && !defined(NO_AES) && \
    (defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA))
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_OBJECT_CLASS privKeyClass   = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS pubKeyClass    = CKO_PUBLIC_KEY;
static CK_BBOOL ckTrue  = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_KEY_TYPE aesKeyType = CKK_AES;
static CK_KEY_TYPE rsaKeyType = CKK_RSA;

static void destroy_obj(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* obj)
{
    if (*obj != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, *obj);
        *obj = CK_INVALID_HANDLE;
    }
}

/* An unwrap template that omits CKA_TOKEN creates session objects, including
 * the companion RSA public key. */
static void test_unwrap_rsa_token_default(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_AES_KEY_WRAP_PAD, NULL, 0 };
    CK_OBJECT_HANDLE wrappingKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubKey = CK_INVALID_HANDLE;
    byte wrapped[2048];
    CK_ULONG wrappedLen = sizeof(wrapped);
    CK_ULONG count = 0;
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_WRAP,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_UNWRAP,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_PRIVATE,  &ckFalse,        sizeof(ckFalse)        },
        { CKA_TOKEN,    &ckFalse,        sizeof(ckFalse)        },
        { CKA_VALUE,    (void*)aes_cbc_key, sizeof(aes_cbc_key) },
    };
    CK_ATTRIBUTE rsaTmpl[] = {
        { CKA_CLASS,            &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,         &rsaKeyType,       sizeof(rsaKeyType)        },
        { CKA_DECRYPT,          &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        { CKA_EXTRACTABLE,      &ckTrue,           sizeof(ckTrue)            },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
        { CKA_TOKEN,            &ckFalse,          sizeof(ckFalse)           },
    };
    CK_ATTRIBUTE unwrapTmpl[] = {
        { CKA_CLASS,    &privKeyClass, sizeof(privKeyClass) },
        { CKA_KEY_TYPE, &rsaKeyType,   sizeof(rsaKeyType)   },
        { CKA_PRIVATE,  &ckFalse,      sizeof(ckFalse)      },
    };
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS,    &pubKeyClass, sizeof(pubKeyClass) },
        { CKA_KEY_TYPE, &rsaKeyType,  sizeof(rsaKeyType)  },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
    };

    rv = funcList->C_CreateObject(session, aesTmpl,
                                  sizeof(aesTmpl) / sizeof(*aesTmpl),
                                  &wrappingKey);
    CHECK_RV(rv, "create AES wrapping key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, rsaTmpl,
                                      sizeof(rsaTmpl) / sizeof(*rsaTmpl),
                                      &privKey);
        CHECK_RV(rv, "create RSA private key", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_WrapKey(session, &mech, wrappingKey, privKey,
                                 wrapped, &wrappedLen);
        CHECK_RV(rv, "wrap RSA private key", CKR_OK);
    }
    destroy_obj(session, &privKey);
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &mech, wrappingKey, wrapped,
                                   wrappedLen, unwrapTmpl,
                                   sizeof(unwrapTmpl) / sizeof(*unwrapTmpl),
                                   &unwrapped);
        CHECK_RV(rv, "unwrap RSA private key without CKA_TOKEN", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjectsInit(session, findTmpl,
                                         sizeof(findTmpl) / sizeof(*findTmpl));
        CHECK_RV(rv, "find companion public key init", CKR_OK);
        if (rv == CKR_OK) {
            rv = funcList->C_FindObjects(session, &pubKey, 1, &count);
            CHECK_RV(rv, "find companion public key", CKR_OK);
            funcList->C_FindObjectsFinal(session);
        }
        CHECK_TRUE(count == 1, "companion public key is a session object");
        if (count != 1)
            pubKey = CK_INVALID_HANDLE;
    }

    destroy_obj(session, &pubKey);
    destroy_obj(session, &unwrapped);
    destroy_obj(session, &wrappingKey);
}
#endif

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
#if defined(WOLFPKCS11_KEYPAIR_GEN_COMMON_LABEL) && \
    defined(HAVE_AES_KEYWRAP) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(NO_RSA) && !defined(NO_AES) && \
    (defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA))
        test_unwrap_rsa_token_default(session);
#endif
    }

    if (session != 0)
        funcList->C_CloseSession(session);
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

    printf("=== wolfPKCS11 attribute validation test ===\n");
    run_test();
    return pkcs11_test_summary();
}
