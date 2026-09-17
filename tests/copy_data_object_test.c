/* copy_data_object_test.c
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
 * Copying a data object must reproduce its payload attributes (value,
 * application, and object id) in the copy.
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

#define TEST_DIR "./store/copy_data_object_test"

static const byte valueData[]   = "the-quick-brown-fox-payload";
static const byte appData[]     = "wolfPKCS11-test-application";
static const byte objectIdData[] = { 0x2A, 0x03, 0x04, 0x05, 0x06, 0x07 };

static int check_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                      CK_ATTRIBUTE_TYPE type, const byte* expect,
                      CK_ULONG expectLen, const char* name)
{
    CK_RV rv;
    byte buf[64];
    CK_ATTRIBUTE attr;

    attr.type = type;
    attr.pValue = buf;
    attr.ulValueLen = sizeof(buf);
    rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    CHECK_RV(rv, name, CKR_OK);
    if (rv != CKR_OK)
        return -1;
    CHECK_TRUE(attr.ulValueLen == expectLen &&
               XMEMCMP(buf, expect, expectLen) == 0, name);
    return 0;
}

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,       &dataClass,          sizeof(dataClass)        },
        { CKA_TOKEN,       &ckFalse,            sizeof(ckFalse)          },
        { CKA_PRIVATE,     &ckFalse,            sizeof(ckFalse)          },
        { CKA_VALUE,       (void*)valueData,    sizeof(valueData) - 1    },
        { CKA_APPLICATION, (void*)appData,      sizeof(appData) - 1      },
        { CKA_OBJECT_ID,   (void*)objectIdData, sizeof(objectIdData)     },
    };
    CK_ULONG createTmplCnt = sizeof(createTmpl) / sizeof(*createTmpl);

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CreateObject(session, createTmpl, createTmplCnt, &obj);
    CHECK_RV(rv, "C_CreateObject(data object)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CopyObject(session, obj, NULL, 0, &copy);
    CHECK_RV(rv, "C_CopyObject(data object)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    check_attr(session, copy, CKA_VALUE, valueData, sizeof(valueData) - 1,
               "copy preserves CKA_VALUE");
    check_attr(session, copy, CKA_APPLICATION, appData, sizeof(appData) - 1,
               "copy preserves CKA_APPLICATION");
    check_attr(session, copy, CKA_OBJECT_ID, objectIdData,
               sizeof(objectIdData), "copy preserves CKA_OBJECT_ID");

out:
    if (copy != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copy);
    if (obj != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, obj);
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

    printf("=== wolfPKCS11 C_CopyObject data-object payload test ===\n");
    run_test();
    return pkcs11_test_summary();
}
