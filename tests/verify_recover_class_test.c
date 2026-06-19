/* verify_recover_class_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
 * Regression test for issue F-4067: a handle that resolves to a valid object
 * of the wrong CKA_CLASS for C_VerifyRecoverInit must report
 * CKR_KEY_TYPE_INCONSISTENT.
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

#define TEST_DIR "./store/verify_recover_class_test"

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    byte keyData[16] = { 0 };
    CK_ATTRIBUTE secretTmpl[] = {
        { CKA_CLASS,       &secretClass,  sizeof(secretClass)  },
        { CKA_KEY_TYPE,    &genericType,  sizeof(genericType)  },
        { CKA_VALUE,       keyData,       sizeof(keyData)      },
        { CKA_EXTRACTABLE, &ckTrue,       sizeof(ckTrue)       },
        /* Public so the object is reachable without C_Login. */
        { CKA_PRIVATE,     &ckFalse,      sizeof(ckFalse)      },
    };
    CK_ULONG secretTmplCnt = sizeof(secretTmpl) / sizeof(*secretTmpl);

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CreateObject(session, secretTmpl, secretTmplCnt, &secret);
    CHECK_RV(rv, "C_CreateObject(secret key)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_RSA_PKCS;

    /* A secret key is the wrong object class for verify-recover. */
    rv = funcList->C_VerifyRecoverInit(session, &mech, secret);
    CHECK_RV(rv, "C_VerifyRecoverInit(secret key handle)",
             CKR_KEY_TYPE_INCONSISTENT);

out:
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

    printf("=== wolfPKCS11 C_VerifyRecoverInit wrong-class test ===\n");
    run_test();
    return pkcs11_test_summary();
}
