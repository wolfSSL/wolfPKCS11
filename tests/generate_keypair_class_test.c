/* generate_keypair_class_test.c
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
 * C_GenerateKeyPair must reject public or private templates whose CKA_CLASS
 * or CKA_KEY_TYPE is inconsistent with the mechanism.
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

#define TEST_DIR "./store/generate_keypair_class_test"

#ifdef HAVE_ECC
static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_BBOOL ckTrue = CK_TRUE;

    CK_ATTRIBUTE goodPub[] = {
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_CLASS,     &pubClass,       sizeof(pubClass)        },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)          },
    };
    CK_ATTRIBUTE goodPriv[] = {
        { CKA_CLASS,    &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ecType,    sizeof(ecType)    },
        { CKA_PRIVATE,  &ckFalse,   sizeof(ckFalse)   },
    };
    CK_ATTRIBUTE badPub[] = {
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_CLASS,     &privClass,      sizeof(privClass)       },
    };
    CK_ATTRIBUTE badPriv[] = {
        { CKA_CLASS,   &pubClass, sizeof(pubClass) },
        { CKA_PRIVATE, &ckFalse,  sizeof(ckFalse)  },
    };
    CK_ATTRIBUTE badPubType[] = {
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_KEY_TYPE,  &rsaType,        sizeof(rsaType)         },
    };
    CK_ATTRIBUTE dupPub[] = {
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_CLASS,     &pubClass,       sizeof(pubClass)        },
        { CKA_CLASS,     &dataClass,      sizeof(dataClass)       },
    };
    CK_ATTRIBUTE simplePriv[] = {
        { CKA_PRIVATE, &ckTrue, sizeof(ckTrue) },
    };

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_GenerateKeyPair(session, &mech,
             badPub, sizeof(badPub) / sizeof(*badPub),
             simplePriv, sizeof(simplePriv) / sizeof(*simplePriv),
             &pub, &priv);
    CHECK_RV(rv, "public template wrong CKA_CLASS", CKR_TEMPLATE_INCONSISTENT);

    rv = funcList->C_GenerateKeyPair(session, &mech,
             goodPub, sizeof(goodPub) / sizeof(*goodPub),
             badPriv, sizeof(badPriv) / sizeof(*badPriv),
             &pub, &priv);
    CHECK_RV(rv, "private template wrong CKA_CLASS", CKR_TEMPLATE_INCONSISTENT);

    rv = funcList->C_GenerateKeyPair(session, &mech,
             badPubType, sizeof(badPubType) / sizeof(*badPubType),
             simplePriv, sizeof(simplePriv) / sizeof(*simplePriv),
             &pub, &priv);
    CHECK_RV(rv, "public template wrong CKA_KEY_TYPE",
             CKR_TEMPLATE_INCONSISTENT);

    rv = funcList->C_GenerateKeyPair(session, &mech,
             dupPub, sizeof(dupPub) / sizeof(*dupPub),
             simplePriv, sizeof(simplePriv) / sizeof(*simplePriv),
             &pub, &priv);
    CHECK_RV(rv, "public template duplicate CKA_CLASS",
             CKR_TEMPLATE_INCONSISTENT);

    rv = funcList->C_GenerateKeyPair(session, &mech,
             goodPub, sizeof(goodPub) / sizeof(*goodPub),
             goodPriv, sizeof(goodPriv) / sizeof(*goodPriv),
             &pub, &priv);
    CHECK_RV(rv, "consistent templates", CKR_OK);

out:
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
    pkcs11_unload();
    return 0;
}
#endif /* HAVE_ECC */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 C_GenerateKeyPair class consistency test ===\n");
#ifdef HAVE_ECC
    run_test();
#else
    printf("ECC not compiled in!\n");
#endif
    return pkcs11_test_summary();
}
