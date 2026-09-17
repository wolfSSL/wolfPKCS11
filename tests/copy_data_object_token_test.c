/* copy_data_object_token_test.c
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
 * Copying a token data object reproduces its common attributes and payload.
 * This exercises the copy path that reads the source object under its lock.
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

#define TEST_DIR "./store/copy_data_object_token_test"

#ifndef WOLFPKCS11_NO_STORE

static CK_SLOT_ID slot = 0;
static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "copy-data-token";

static const byte valueData[]    = "token-data-value-payload";
static const byte idData[]       = { 0x0A, 0x0B, 0x0C, 0x0D };
static const char objLabel[]     = "copy-data-token-object";
static const byte objectIdData[] = { 0x51, 0x52, 0x53 };

static CK_RV token_setup(void)
{
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE soSession = 0;
    unsigned char label[32];
    CK_RV rv;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv != CKR_OK)
        return rv;
    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv != CKR_OK)
        return rv;
    if (slotCount == 0)
        return CKR_TOKEN_NOT_PRESENT;
    slot = slotList[0];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin), label);
    if (rv != CKR_OK)
        return rv;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &soSession);
    if (rv != CKR_OK)
        return rv;
    rv = funcList->C_Login(soSession, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                           (CK_ULONG)XSTRLEN(soPin));
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
    }
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    return rv;
}

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
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,       &dataClass,          sizeof(dataClass)     },
        { CKA_TOKEN,       &ckTrue,             sizeof(ckTrue)        },
        { CKA_PRIVATE,     &ckFalse,            sizeof(ckFalse)       },
        { CKA_LABEL,       (void*)objLabel,     sizeof(objLabel) - 1  },
        { CKA_ID,          (void*)idData,       sizeof(idData)        },
        { CKA_VALUE,       (void*)valueData,    sizeof(valueData) - 1 },
        { CKA_OBJECT_ID,   (void*)objectIdData, sizeof(objectIdData)  },
    };
    CK_ULONG createTmplCnt = sizeof(createTmpl) / sizeof(*createTmpl);

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = token_setup();
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                           (CK_ULONG)XSTRLEN(userPin));
    CHECK_RV(rv, "login user", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CreateObject(session, createTmpl, createTmplCnt, &obj);
    CHECK_RV(rv, "C_CreateObject(token data object)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CopyObject(session, obj, NULL, 0, &copy);
    CHECK_RV(rv, "C_CopyObject(token data object)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    check_attr(session, copy, CKA_LABEL, (const byte*)objLabel,
               sizeof(objLabel) - 1, "copy preserves CKA_LABEL");
    check_attr(session, copy, CKA_ID, idData, sizeof(idData),
               "copy preserves CKA_ID");
    check_attr(session, copy, CKA_VALUE, valueData, sizeof(valueData) - 1,
               "copy preserves CKA_VALUE");
    check_attr(session, copy, CKA_OBJECT_ID, objectIdData,
               sizeof(objectIdData), "copy preserves CKA_OBJECT_ID");

out:
    if (copy != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copy);
    if (obj != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, obj);
    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    funcList->C_Finalize(NULL);
    pkcs11_unload();
    return 0;
}
#endif /* !WOLFPKCS11_NO_STORE */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 token data-object copy test ===\n");
#ifndef WOLFPKCS11_NO_STORE
    run_test();
#else
    printf("KeyStore not compiled in!\n");
#endif
    return pkcs11_test_summary();
}
