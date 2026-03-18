/* find_objects_null_template_test.c
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
 * Test for C_FindObjectsInit with NULL template (issue #816).
 *
 * Per PKCS#11 v3.0 spec, C_FindObjectsInit(hSession, NULL_PTR, 0) should
 * match all objects. The current implementation unconditionally rejects
 * pTemplate == NULL with CKR_ARGUMENTS_BAD, even when ulCount == 0.
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

#define FIND_NULL_TEST_DIR "./store/find_null_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

static int test_passed = 0;
static int test_failed = 0;

#define CHECK_CKR(rv, op, expected) do {                    \
    if (rv != expected) {                                   \
        fprintf(stderr, "FAIL: %s: expected %ld, got %ld\n", op, (long)expected, (long)rv); \
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
static byte* userPin = (byte*)"someUserPin";
static int userPinLen = 11;

static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_OBJECT_CLASS dataClass = CKO_DATA;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;

/* Test key data */
static unsigned char testKeyData[32] = {
    0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
    0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
    0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
};

static unsigned char keyId[] = {0xDE, 0xAD, 0xBE, 0xEF};
static char keyLabel[] = "find-null-test-key";

/* Test data object content */
static unsigned char testDataValue[] = "test data object for find-null";
static char dataLabel[] = "find-null-test-data";

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_INFO info;
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

    ret = funcList->C_GetInfo(&info);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (ret != CKR_OK)
        return ret;

    if (slotCount > 0) {
        slot = slotList[0];
    } else {
        fprintf(stderr, "No slots available\n");
        return CKR_GENERAL_ERROR;
    }

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

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, session);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    if (ret != CKR_OK) {
        funcList->C_CloseSession(*session);
        return ret;
    }

    return CKR_OK;
}

static CK_RV pkcs11_close_session(CK_SESSION_HANDLE session)
{
    funcList->C_Logout(session);
    return funcList->C_CloseSession(session);
}

/* Remove token file so C_InitToken sees an uninitialized token. */
static void cleanup_test_files(const char* dir)
{
    char filepath[512];

    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", dir,
             WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

static CK_RV create_secret_key(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass,  sizeof(secretKeyClass)  },
        { CKA_KEY_TYPE,    &genericKeyType,  sizeof(genericKeyType)  },
        { CKA_TOKEN,       &ckFalse,         sizeof(ckFalse)         },
        { CKA_PRIVATE,     &ckFalse,         sizeof(ckFalse)         },
        { CKA_SENSITIVE,   &ckFalse,         sizeof(ckFalse)         },
        { CKA_EXTRACTABLE, &ckTrue,          sizeof(ckTrue)          },
        { CKA_SIGN,        &ckTrue,          sizeof(ckTrue)          },
        { CKA_VERIFY,      &ckTrue,          sizeof(ckTrue)          },
        { CKA_VALUE,       testKeyData,      sizeof(testKeyData)     },
        { CKA_ID,          keyId,            sizeof(keyId)           },
        { CKA_LABEL,       keyLabel,         sizeof(keyLabel)-1      }
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

static CK_RV create_data_object(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE* obj)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass,     sizeof(dataClass)          },
        { CKA_TOKEN,   &ckFalse,       sizeof(ckFalse)            },
        { CKA_PRIVATE, &ckFalse,       sizeof(ckFalse)            },
        { CKA_VALUE,   testDataValue,  sizeof(testDataValue)-1    },
        { CKA_LABEL,   dataLabel,      sizeof(dataLabel)-1        }
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, obj);
}

static int find_objects_null_template_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key, dataObj;
    CK_OBJECT_HANDLE found[10];
    CK_ULONG foundCount;
    int result = 0;

    printf("\n=== Testing C_FindObjectsInit with NULL template ===\n");

    cleanup_test_files(FIND_NULL_TEST_DIR);

    ret = pkcs11_init();
    CHECK_CKR(ret, "C_Initialize", CKR_OK);

    ret = pkcs11_init_token();
    CHECK_CKR(ret, "C_InitToken", CKR_OK);

    /* Set user PIN via SO session */
    {
        CK_SESSION_HANDLE soSession;
        int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

        ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &soSession);
        CHECK_CKR(ret, "C_OpenSession (SO)", CKR_OK);

        ret = funcList->C_Login(soSession, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "C_Login (SO)", CKR_OK);

        ret = funcList->C_InitPIN(soSession, userPin, userPinLen);
        CHECK_CKR(ret, "C_InitPIN", CKR_OK);

        funcList->C_Logout(soSession);
        funcList->C_CloseSession(soSession);
    }

    ret = pkcs11_open_session(&session);
    CHECK_CKR(ret, "C_OpenSession (user)", CKR_OK);

    /* Create two different object types */
    ret = create_secret_key(session, &key);
    CHECK_CKR(ret, "C_CreateObject (secret key)", CKR_OK);

    ret = create_data_object(session, &dataObj);
    CHECK_CKR(ret, "C_CreateObject (data object)", CKR_OK);

    /*
     * Test 1: C_FindObjectsInit(session, NULL, 0) should return CKR_OK
     * per PKCS#11 spec — NULL template with count 0 means "match all".
     *
     * BUG: Currently returns CKR_ARGUMENTS_BAD (see src/crypto.c:1598).
     */
    ret = funcList->C_FindObjectsInit(session, NULL_PTR, 0);
    CHECK_CKR(ret, "C_FindObjectsInit(NULL, 0) [spec: match all]", CKR_OK);

    ret = funcList->C_FindObjects(session, found, 10, &foundCount);
    CHECK_CKR(ret, "C_FindObjects [expect >= 2 objects]", CKR_OK);

    if (foundCount < 2) {
        fprintf(stderr, "FAIL: C_FindObjects: expected >= 2 objects, "
                "found %lu\n", (unsigned long)foundCount);
        test_failed++;
        result = -1;
    } else {
        printf("PASS: C_FindObjects found %lu objects (>= 2)\n",
               (unsigned long)foundCount);
        test_passed++;
    }

    ret = funcList->C_FindObjectsFinal(session);
    CHECK_CKR(ret, "C_FindObjectsFinal", CKR_OK);

    /*
     * Test 2: C_FindObjectsInit(session, NULL, non_zero) should still
     * return CKR_ARGUMENTS_BAD — a non-zero count with NULL template
     * is a genuine error.
     */
    ret = funcList->C_FindObjectsInit(session, NULL_PTR, 5);
    CHECK_CKR(ret, "C_FindObjectsInit(NULL, 5) [expect ARGUMENTS_BAD]",
              CKR_ARGUMENTS_BAD);

cleanup:
    if (session != 0)
        pkcs11_close_session(session);
    pkcs11_final();
    return result;
}

static void print_results(void)
{
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);

    if (test_failed == 0) {
        printf("ALL TESTS PASSED!\n");
    } else {
        printf("SOME TESTS FAILED!\n");
    }
}

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", FIND_NULL_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 C_FindObjectsInit NULL Template Test ===\n");

    (void)find_objects_null_template_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}
