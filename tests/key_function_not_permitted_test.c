/* key_function_not_permitted_test.c
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
 * Regression test for issue F-6052: an operation denied by a key's CKA_<op>
 * usage attribute must report CKR_KEY_FUNCTION_NOT_PERMITTED, distinct from
 * the key-type mismatch case (CKR_KEY_TYPE_INCONSISTENT).
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

#define TEST_DIR "./store/key_function_not_permitted_test"

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckFalse = CK_FALSE;
    byte keyData[16] = { 0 };
    byte iv[16] = { 0 };
    CK_MECHANISM mech;
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    keyData,      sizeof(keyData)     },
        /* Correct key type for the mechanism, but usage is denied. */
        { CKA_ENCRYPT,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_DECRYPT,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ULONG aesTmplCnt = sizeof(aesTmpl) / sizeof(*aesTmpl);

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CreateObject(session, aesTmpl, aesTmplCnt, &aesKey);
    CHECK_RV(rv, "C_CreateObject(AES, encrypt/decrypt off)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_AES_CBC;
    mech.pParameter = iv;
    mech.ulParameterLen = sizeof(iv);

    rv = funcList->C_EncryptInit(session, &mech, aesKey);
    CHECK_RV(rv, "C_EncryptInit(CKA_ENCRYPT=FALSE)",
             CKR_KEY_FUNCTION_NOT_PERMITTED);

    rv = funcList->C_DecryptInit(session, &mech, aesKey);
    CHECK_RV(rv, "C_DecryptInit(CKA_DECRYPT=FALSE)",
             CKR_KEY_FUNCTION_NOT_PERMITTED);

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

    printf("=== wolfPKCS11 key-function-not-permitted test ===\n");
    run_test();
    return pkcs11_test_summary();
}
