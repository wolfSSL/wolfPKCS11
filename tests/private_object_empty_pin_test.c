/* private_object_empty_pin_test.c
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
 * Test for issue F-3835: an empty user PIN must not silently disable
 * CKA_PRIVATE access control. A public (un-logged-in) session must not be
 * able to discover (C_FindObjects) or resolve by handle
 * (C_GetAttributeValue) an object marked CKA_PRIVATE=TRUE, even when the
 * token has a zero-length user PIN. Logging in - which is still possible
 * with an empty PIN - grants access.
 *
 * The empty-PIN scenario requires a build with WP11_MIN_PIN_LEN=0 (the
 * default for WOLFPKCS11_NSS builds). When the token enforces a minimum PIN
 * length the empty PIN cannot be set and the test reports itself skipped.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>

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

#define TEST_DIR "./store/private_object_empty_pin_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

static int test_passed = 0;
static int test_failed = 0;
static int test_skipped = 0;

#define CHECK_CKR(rv, op, expected) do {                    \
    if (rv != expected) {                                   \
        fprintf(stderr, "FAIL: %s: expected 0x%lx, got 0x%lx\n", op, \
                (unsigned long)(expected), (unsigned long)(rv)); \
        test_failed++;                                      \
        result = -1;                                        \
        goto cleanup;                                       \
    } else {                                                \
        printf("PASS: %s\n", op);                           \
        test_passed++;                                      \
    }                                                       \
} while(0)

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static const char* tokenName = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;

/* Empty user PIN - the scenario under test. */
static byte* userPin = (byte*)"";
static int userPinLen = 0;

static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static unsigned char keyId[] = {0xDE, 0xAD, 0xBE, 0xEF};

static unsigned char testKeyData[32] = {
    0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
    0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
    0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
};

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);

#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return -1;
    }

    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        return -1;
    }

    ret = func(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: 0x%lx\n",
            (unsigned long)ret);
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: 0x%lx\n",
            (unsigned long)ret);
        return ret;
    }
#endif

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (ret != CKR_OK)
        return ret;

    if (slotCount == 0) {
        fprintf(stderr, "No slots available\n");
        return CKR_GENERAL_ERROR;
    }
    slot = slotList[0];

    return ret;
}

static CK_RV pkcs11_final(void)
{
    if (funcList != NULL) {
        funcList->C_Finalize(NULL);
        funcList = NULL;
    }
#ifndef HAVE_PKCS11_STATIC
    if (dlib) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
    return CKR_OK;
}

static CK_RV pkcs11_init_token(void)
{
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));

    return funcList->C_InitToken(slot, soPin, soPinLen, label);
}

static CK_RV pkcs11_set_empty_user_pin(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
    if (ret != CKR_OK) {
        funcList->C_CloseSession(session);
        return ret;
    }

    ret = funcList->C_InitPIN(session, userPin, userPinLen);
    funcList->C_Logout(session);
    funcList->C_CloseSession(session);
    return ret;
}

static CK_RV create_private_token_key(CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass,  sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType,  sizeof(genericKeyType) },
        { CKA_TOKEN,       &ckTrue,          sizeof(ckTrue)         },
        { CKA_PRIVATE,     &ckTrue,          sizeof(ckTrue)         },
        { CKA_SENSITIVE,   &ckFalse,         sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,          sizeof(ckTrue)         },
        { CKA_VALUE,       testKeyData,      sizeof(testKeyData)    },
        { CKA_ID,          keyId,            sizeof(keyId)          },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

/* Count objects matching the CKA_ID of the private key. */
static CK_RV count_private_key(CK_SESSION_HANDLE session, CK_ULONG* countOut)
{
    CK_RV ret;
    CK_OBJECT_HANDLE found[4];
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType) },
        { CKA_ID,       keyId,           sizeof(keyId)          },
    };

    ret = funcList->C_FindObjectsInit(session, tmpl,
                                      sizeof(tmpl) / sizeof(*tmpl));
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_FindObjects(session, found,
                                  sizeof(found) / sizeof(*found), &count);
    if (ret != CKR_OK) {
        funcList->C_FindObjectsFinal(session);
        return ret;
    }

    ret = funcList->C_FindObjectsFinal(session);
    if (ret != CKR_OK)
        return ret;

    *countOut = count;
    return CKR_OK;
}

static void cleanup_test_files(const char* dir)
{
    char filepath[512];

    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", dir,
             WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

static int private_object_empty_pin_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG count;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int result = 0;

    printf("\n=== Testing CKA_PRIVATE enforcement with empty user PIN ===\n");

    cleanup_test_files(TEST_DIR);

    ret = pkcs11_init();
    CHECK_CKR(ret, "C_Initialize", CKR_OK);

    ret = pkcs11_init_token();
    CHECK_CKR(ret, "C_InitToken", CKR_OK);

    {
        CK_TOKEN_INFO tokenInfo;
        ret = funcList->C_GetTokenInfo(slot, &tokenInfo);
        CHECK_CKR(ret, "C_GetTokenInfo", CKR_OK);
        if (tokenInfo.ulMinPinLen > 0) {
            printf("Skipping: token requires minimum PIN length %lu "
                   "(empty PIN not allowed)\n",
                   (unsigned long)tokenInfo.ulMinPinLen);
            test_skipped = 1;
            pkcs11_final();
            return 0;
        }
    }

    ret = pkcs11_set_empty_user_pin();
    CHECK_CKR(ret, "C_InitPIN (empty)", CKR_OK);

    /* Open a public (un-logged-in) session. With an empty PIN the token
     * reports CKF_LOGIN_REQUIRED off, so this is the canonical empty-PIN
     * usage: never call C_Login. The object stays decoded in memory. */
    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession (public)", CKR_OK);

    ret = create_private_token_key(session, &key);
    CHECK_CKR(ret, "C_CreateObject (CKA_PRIVATE=TRUE)", CKR_OK);

    /* Security check 1 (discovery): C_FindObjects must not reveal the
     * CKA_PRIVATE object to a public session, even with an empty PIN. */
    ret = count_private_key(session, &count);
    CHECK_CKR(ret, "C_FindObjects (public session)", CKR_OK);
    if (count != 0) {
        fprintf(stderr, "FAIL: public session discovered %lu CKA_PRIVATE "
                "object(s) under empty PIN (expected 0)\n",
                (unsigned long)count);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: public session cannot discover the private key\n");
    test_passed++;

#ifndef WOLFPKCS11_NSS
    /* Security check 2 (lookup by handle): resolving the object by handle
     * must also be denied for a public session. (Skipped under
     * WOLFPKCS11_NSS, which resolves private objects by handle as the
     * internal crypto module and does not call C_Login.) */
    {
        CK_OBJECT_CLASS gotClass;
        CK_ATTRIBUTE getTmpl[] = {
            { CKA_CLASS, &gotClass, sizeof(gotClass) },
        };
        ret = funcList->C_GetAttributeValue(session, key, getTmpl, 1);
        if (ret == CKR_OK) {
            fprintf(stderr, "FAIL: public session resolved CKA_PRIVATE object "
                    "by handle under empty PIN (expected failure)\n");
            test_failed++;
            result = -1;
            goto cleanup;
        }
        printf("PASS: public session cannot resolve the private key by handle "
               "(got 0x%lx)\n", (unsigned long)ret);
        test_passed++;
    }
#endif

    /* Logging in - which an empty PIN still permits - grants access. */
    ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_CKR(ret, "C_Login (USER, empty PIN)", CKR_OK);

    ret = count_private_key(session, &count);
    CHECK_CKR(ret, "C_FindObjects (logged in)", CKR_OK);
    if (count != 1) {
        fprintf(stderr, "FAIL: logged-in session should find 1 private key, "
                "found %lu\n", (unsigned long)count);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: login with empty PIN grants access to the private key\n");
    test_passed++;

    {
        unsigned char value[64];
        CK_ATTRIBUTE getTmpl[] = {
            { CKA_VALUE, value, sizeof(value) },
        };
        ret = funcList->C_GetAttributeValue(session, key, getTmpl, 1);
        CHECK_CKR(ret, "C_GetAttributeValue (logged in)", CKR_OK);
        if (getTmpl[0].ulValueLen != sizeof(testKeyData) ||
                XMEMCMP(value, testKeyData, sizeof(testKeyData)) != 0) {
            fprintf(stderr, "FAIL: key value mismatch after login\n");
            test_failed++;
            result = -1;
            goto cleanup;
        }
        printf("PASS: logged-in session reads the private key value\n");
        test_passed++;
    }

cleanup:
    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();
    return result;
}

static void print_results(void)
{
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    if (test_skipped != 0)
        printf("Tests skipped: %d\n", test_skipped);

    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");
}

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 CKA_PRIVATE Empty PIN Test ===\n");

    (void)private_object_empty_pin_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}
