/* data_object_partial_update_test.c
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
 * Updating one attribute of a data object must leave the attributes the
 * template omits unchanged, while a supplied empty attribute clears that one.
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

#define TEST_DIR "./store/data_object_partial_update_test"

static const byte valueData[]   = "original-value";
static const byte appData[]     = "original-application";
static const byte objectIdData[] = { 0x11, 0x22, 0x33, 0x44 };
static const byte newValue[]    = "updated-value-payload";

static int expect_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
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
               (expectLen == 0 || XMEMCMP(buf, expect, expectLen) == 0), name);
    return 0;
}

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,       &dataClass,          sizeof(dataClass)     },
        { CKA_TOKEN,       &ckFalse,            sizeof(ckFalse)       },
        { CKA_PRIVATE,     &ckFalse,            sizeof(ckFalse)       },
        { CKA_VALUE,       (void*)valueData,    sizeof(valueData) - 1 },
        { CKA_APPLICATION, (void*)appData,      sizeof(appData) - 1   },
        { CKA_OBJECT_ID,   (void*)objectIdData, sizeof(objectIdData)  },
    };
    CK_ULONG createTmplCnt = sizeof(createTmpl) / sizeof(*createTmpl);
    CK_ATTRIBUTE setValueOnly[] = {
        { CKA_VALUE, (void*)newValue, sizeof(newValue) - 1 },
    };
    CK_ATTRIBUTE clearApp[] = {
        { CKA_APPLICATION, NULL, 0 },
    };

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

    /* Update only CKA_VALUE; the other two attributes must survive. */
    rv = funcList->C_SetAttributeValue(session, obj, setValueOnly, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_VALUE only)", CKR_OK);

    expect_attr(session, obj, CKA_VALUE, newValue, sizeof(newValue) - 1,
                "CKA_VALUE updated");
    expect_attr(session, obj, CKA_APPLICATION, appData, sizeof(appData) - 1,
                "CKA_APPLICATION preserved");
    expect_attr(session, obj, CKA_OBJECT_ID, objectIdData,
                sizeof(objectIdData), "CKA_OBJECT_ID preserved");

    /* A supplied empty attribute clears only that attribute. */
    rv = funcList->C_SetAttributeValue(session, obj, clearApp, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_APPLICATION empty)", CKR_OK);

    expect_attr(session, obj, CKA_APPLICATION, NULL, 0,
                "CKA_APPLICATION cleared");
    expect_attr(session, obj, CKA_VALUE, newValue, sizeof(newValue) - 1,
                "CKA_VALUE still present after clearing application");
    expect_attr(session, obj, CKA_OBJECT_ID, objectIdData,
                sizeof(objectIdData), "CKA_OBJECT_ID still present");

out:
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

    printf("=== wolfPKCS11 data-object partial update test ===\n");
    run_test();
    return pkcs11_test_summary();
}
