/* create_object_class_test.c
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
 * Regression test for issues F-5513 and F-5516: a C_CreateObject key template
 * that omits CKA_CLASS must be rejected with CKR_TEMPLATE_INCOMPLETE.
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

#define TEST_DIR "./store/create_object_class_test"

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    CK_BBOOL ckFalse = CK_FALSE;
    byte keyData[16] = { 0 };
    CK_ATTRIBUTE noClassTmpl[] = {
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_VALUE,    keyData,      sizeof(keyData)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)      },
    };
    CK_ULONG noClassTmplCnt = sizeof(noClassTmpl) / sizeof(*noClassTmpl);
    CK_ATTRIBUTE withClassTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_VALUE,    keyData,      sizeof(keyData)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)      },
    };
    CK_ULONG withClassTmplCnt = sizeof(withClassTmpl) / sizeof(*withClassTmpl);

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CreateObject(session, noClassTmpl, noClassTmplCnt, &obj);
    CHECK_RV(rv, "C_CreateObject(no CKA_CLASS)", CKR_TEMPLATE_INCOMPLETE);

    rv = funcList->C_CreateObject(session, withClassTmpl, withClassTmplCnt,
                                  &obj);
    CHECK_RV(rv, "C_CreateObject(with CKA_CLASS)", CKR_OK);

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

    printf("=== wolfPKCS11 C_CreateObject CKA_CLASS test ===\n");
    run_test();
    return pkcs11_test_summary();
}
