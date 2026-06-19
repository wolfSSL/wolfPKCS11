/* set_attr_readonly_test.c
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
 * Regression test for issue F-5517: C_SetAttributeValue must reject a change
 * to a read-only class/identity or generated-state attribute with
 * CKR_ATTRIBUTE_READ_ONLY.
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

#define TEST_DIR "./store/set_attr_readonly_test"

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    byte keyData[16] = { 0 };
    char label[] = "relabel";
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType, sizeof(genericType) },
        { CKA_VALUE,       keyData,      sizeof(keyData)     },
        { CKA_PRIVATE,     &ckFalse,     sizeof(ckFalse)     },
        /* Non-sensitive and extractable, so CKA_ALWAYS_SENSITIVE and
         * CKA_NEVER_EXTRACTABLE are both CK_FALSE after creation. */
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
    };
    CK_ULONG keyTmplCnt = sizeof(keyTmpl) / sizeof(*keyTmpl);

    CK_ATTRIBUTE setClass[]   = { { CKA_CLASS, &dataClass, sizeof(dataClass) } };
    CK_ATTRIBUTE setKeyType[] = { { CKA_KEY_TYPE, &aesType, sizeof(aesType) } };
    CK_ATTRIBUTE setAlwaysSensitive[] =
        { { CKA_ALWAYS_SENSITIVE, &ckTrue, sizeof(ckTrue) } };
    CK_ATTRIBUTE setNeverExtractable[] =
        { { CKA_NEVER_EXTRACTABLE, &ckTrue, sizeof(ckTrue) } };
    CK_ATTRIBUTE setLabel[] =
        { { CKA_LABEL, label, (CK_ULONG)(sizeof(label) - 1) } };
    CK_ATTRIBUTE setSameClass[] =
        { { CKA_CLASS, &secretClass, sizeof(secretClass) } };

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CreateObject(session, keyTmpl, keyTmplCnt, &key);
    CHECK_RV(rv, "C_CreateObject(secret key)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    /* Class/identity attributes are read-only after creation. */
    rv = funcList->C_SetAttributeValue(session, key, setClass, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_CLASS)", CKR_ATTRIBUTE_READ_ONLY);

    rv = funcList->C_SetAttributeValue(session, key, setKeyType, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_KEY_TYPE)",
             CKR_ATTRIBUTE_READ_ONLY);

    /* Generated-state attributes are read-only. */
    rv = funcList->C_SetAttributeValue(session, key, setAlwaysSensitive, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_ALWAYS_SENSITIVE)",
             CKR_ATTRIBUTE_READ_ONLY);

    rv = funcList->C_SetAttributeValue(session, key, setNeverExtractable, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_NEVER_EXTRACTABLE)",
             CKR_ATTRIBUTE_READ_ONLY);

    /* A genuinely modifiable attribute still succeeds. */
    rv = funcList->C_SetAttributeValue(session, key, setLabel, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_LABEL)", CKR_OK);

    /* Setting a read-only attribute to its current value is a no-op. */
    rv = funcList->C_SetAttributeValue(session, key, setSameClass, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_CLASS unchanged)", CKR_OK);

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

    printf("=== wolfPKCS11 C_SetAttributeValue read-only test ===\n");
    run_test();
    return pkcs11_test_summary();
}
