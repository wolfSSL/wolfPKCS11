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
 * Regression test for issue F-5517. SetAttributeValue forwarded every
 * template attribute to WP11_Object_SetAttr, which accepted updates to
 * read-only class/identity and generated-state attributes (CKA_CLASS,
 * CKA_KEY_TYPE, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, ...). Changing
 * those via C_SetAttributeValue must fail with CKR_ATTRIBUTE_READ_ONLY.
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

#define TEST_DIR "./store/set_attr_readonly_test"

static int test_passed = 0;
static int test_failed = 0;

#define CHECK_RV(rv, op, expected) do {                                       \
    if ((rv) != (expected)) {                                                 \
        fprintf(stderr, "FAIL: %s: expected 0x%lx, got 0x%lx\n", op,          \
                (unsigned long)(expected), (unsigned long)(rv));              \
        test_failed++;                                                        \
    } else {                                                                  \
        printf("PASS: %s\n", op);                                             \
        test_passed++;                                                        \
    }                                                                         \
} while (0)

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;

static CK_RV pkcs11_load(void)
{
    CK_RV ret;
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return CKR_GENERAL_ERROR;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        return CKR_GENERAL_ERROR;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK)
        return ret;
#endif
    return CKR_OK;
}

static void pkcs11_unload(void)
{
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
    funcList = NULL;
}

static int run_test(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = 0;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
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
        /* Non-sensitive, extractable: CKA_ALWAYS_SENSITIVE and
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

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    CHECK_RV(rv, "C_GetSlotList", CKR_OK);
    if (rv != CKR_OK || slotCount == 0)
        goto out;
    slot = slotList[0];

    rv = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_RV(rv, "C_OpenSession", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CreateObject(session, keyTmpl, keyTmplCnt, &key);
    CHECK_RV(rv, "C_CreateObject(secret key)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    /* Changing class/identity attributes must be rejected. */
    rv = funcList->C_SetAttributeValue(session, key, setClass, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_CLASS)", CKR_ATTRIBUTE_READ_ONLY);

    rv = funcList->C_SetAttributeValue(session, key, setKeyType, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_KEY_TYPE)",
             CKR_ATTRIBUTE_READ_ONLY);

    /* Changing generated-state attributes must be rejected. */
    rv = funcList->C_SetAttributeValue(session, key, setAlwaysSensitive, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_ALWAYS_SENSITIVE)",
             CKR_ATTRIBUTE_READ_ONLY);

    rv = funcList->C_SetAttributeValue(session, key, setNeverExtractable, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_NEVER_EXTRACTABLE)",
             CKR_ATTRIBUTE_READ_ONLY);

    /* A genuinely modifiable attribute still succeeds. */
    rv = funcList->C_SetAttributeValue(session, key, setLabel, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_LABEL)", CKR_OK);

    /* Setting a read-only attribute to its current value is a no-op, not a
     * change, so it is allowed (this is what C_CopyObject relies on). */
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

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");

    return (test_failed == 0) ? 0 : 1;
}
