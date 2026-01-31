/* empty_pin_store_test.c
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
 * Test for empty PIN scenario with token storage - verifies that encrypted
 * objects can be stored and loaded correctly when using an empty user PIN.
 *
 * Benefit of empty PIN: the application never calls C_Login. The token is
 * usable immediately after C_OpenSession (one fewer API call, no PIN
 * handling). This saves time and simplifies headless/automated use (servers,
 * daemons) where there is no user to enter a PIN.
 *
 * This test exercises that time-saving path: open session, use token objects
 * (create/find, get attributes) without ever calling C_Login.
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

#ifdef _WIN32
    #define PATH_SEP "\\"
#else
    #define PATH_SEP "/"
#endif

#ifndef WOLFPKCS11_DLL_FILENAME
#ifdef __APPLE__
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.dylib"
#else
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.so"
#endif
#endif

#define EMPTY_PIN_TEST_DIR "./store/empty_pin_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

#if !defined(WOLFPKCS11_NO_STORE)

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

/* Empty user PIN - this is the key scenario we're testing */
static byte* userPin = (byte*)"";
static int userPinLen = 0;

static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;

/* Test key data */
static unsigned char testKeyData[32] = {
    0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
    0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
    0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
};

/* Key ID for persistence */
static unsigned char keyId[] = {0xDE, 0xAD, 0xBE, 0xEF};
static char keyLabel[] = "empty-pin-test-key";

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

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, session);
    if (ret != CKR_OK)
        return ret;

    /* With empty PIN, no login is required; skip C_Login when userPinLen is 0 */
    if (userPinLen != 0) {
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
        if (ret != CKR_OK)
            return ret;
    }

    return CKR_OK;
}

static CK_RV pkcs11_close_session(CK_SESSION_HANDLE session)
{
    /* Logout may fail if not logged in (empty PIN case) */
    funcList->C_Logout(session);
    return funcList->C_CloseSession(session);
}

static CK_RV create_token_secret_key(CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE* key)
{
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass,  sizeof(secretKeyClass)     },
        { CKA_KEY_TYPE,    &genericKeyType,  sizeof(genericKeyType)     },
        { CKA_TOKEN,       &ckTrue,          sizeof(ckTrue)             },
        { CKA_PRIVATE,     &ckTrue,          sizeof(ckTrue)             },
        { CKA_SENSITIVE,   &ckFalse,         sizeof(ckFalse)            },
        { CKA_EXTRACTABLE, &ckTrue,          sizeof(ckTrue)             },
        { CKA_SIGN,        &ckTrue,          sizeof(ckTrue)             },
        { CKA_VERIFY,      &ckTrue,          sizeof(ckTrue)             },
        { CKA_VALUE,       testKeyData,      sizeof(testKeyData)        },
        { CKA_ID,          keyId,            sizeof(keyId)              },
        { CKA_LABEL,       keyLabel,         sizeof(keyLabel)-1         }
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

static CK_RV find_token_secret_key(CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE* key)
{
    CK_RV ret;
    CK_ULONG count;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType) },
        { CKA_ID,       keyId,           sizeof(keyId)          }
    };

    ret = funcList->C_FindObjectsInit(session, tmpl,
                                      sizeof(tmpl)/sizeof(CK_ATTRIBUTE));
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_FindObjects(session, key, 1, &count);
    if (ret != CKR_OK) {
        funcList->C_FindObjectsFinal(session);
        return ret;
    }

    ret = funcList->C_FindObjectsFinal(session);
    if (ret != CKR_OK)
        return ret;

    if (count != 1) {
        fprintf(stderr, "FAIL: C_FindObjects: expected 1 key, found %lu\n",
                (unsigned long)count);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    return CKR_OK;
}

static CK_RV verify_key_value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    unsigned char value[64];
    CK_ULONG valueLen = sizeof(value);
    CK_ATTRIBUTE tmpl[] = {
        { CKA_VALUE, value, valueLen }
    };

    ret = funcList->C_GetAttributeValue(session, key, tmpl, 1);
    if (ret != CKR_OK)
        return ret;

    if (tmpl[0].ulValueLen != sizeof(testKeyData)) {
        fprintf(stderr, "FAIL: Key value length mismatch: expected %lu, got %lu\n",
                (unsigned long)sizeof(testKeyData),
                (unsigned long)tmpl[0].ulValueLen);
        return CKR_GENERAL_ERROR;
    }

    if (XMEMCMP(value, testKeyData, sizeof(testKeyData)) != 0) {
        fprintf(stderr, "FAIL: Key value data mismatch\n");
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

/* Remove token file so C_InitToken sees an uninitialized token.
 * Otherwise a leftover token from a previous run causes C_InitToken to
 * verify the SO PIN and return CKR_PIN_INCORRECT (0xa0) when it doesn't match.
 */
static void cleanup_test_files(const char* dir)
{
    char filepath[512];

    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", dir, WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

static int empty_pin_store_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session1 = 0, session2 = 0;
    CK_OBJECT_HANDLE key1, key2;
    int result = 0;

    printf("\n=== Testing empty PIN token store ===\n");

    /* Ensure clean store so C_InitToken does fresh init (no SO PIN check) */
    cleanup_test_files(EMPTY_PIN_TEST_DIR);

    ret = pkcs11_init();
    CHECK_CKR(ret, "C_Initialize", CKR_OK);

    ret = pkcs11_init_token();
    CHECK_CKR(ret, "C_InitToken", CKR_OK);

    {
        CK_TOKEN_INFO tokenInfo;
        ret = funcList->C_GetTokenInfo(slot, &tokenInfo);
        CHECK_CKR(ret, "C_GetTokenInfo", CKR_OK);
        if (tokenInfo.ulMinPinLen > 0) {
            printf("Skipping empty PIN test: token requires minimum PIN length "
                "%lu (empty PIN not allowed)\n",
                (unsigned long)tokenInfo.ulMinPinLen);
            pkcs11_final();
            return 0;
        }
    }

    ret = pkcs11_set_empty_user_pin();
    CHECK_CKR(ret, "C_InitPIN", CKR_OK);

    ret = pkcs11_open_session(&session1);
    CHECK_CKR(ret, "C_OpenSession", CKR_OK);

    ret = create_token_secret_key(session1, &key1);
    CHECK_CKR(ret, "C_CreateObject", CKR_OK);

    ret = verify_key_value(session1, key1);
    CHECK_CKR(ret, "C_GetAttributeValue (before finalize)", CKR_OK);

    /* Close session and finalize - forces storage to disk */
    pkcs11_close_session(session1);
    session1 = 0;
    pkcs11_final();

    /* Phase 2: Re-initialize, load, verify */
    ret = pkcs11_init();
    CHECK_CKR(ret, "C_Initialize (reload)", CKR_OK);

    ret = pkcs11_open_session(&session2);
    CHECK_CKR(ret, "C_OpenSession (reload)", CKR_OK);

    ret = find_token_secret_key(session2, &key2);
    CHECK_CKR(ret, "C_FindObjects", CKR_OK);

    ret = verify_key_value(session2, key2);
    CHECK_CKR(ret, "C_GetAttributeValue (after reload)", CKR_OK);

cleanup:
    if (session1 != 0)
        pkcs11_close_session(session1);
    if (session2 != 0)
        pkcs11_close_session(session2);
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

#endif /* !WOLFPKCS11_NO_STORE */

int main(int argc, char* argv[])
{
#if !defined(WOLFPKCS11_NO_STORE)
#ifndef WOLFPKCS11_NO_ENV
    /* Always use isolated store so we don't pick up another test's token */
    XSETENV("WOLFPKCS11_TOKEN_PATH", EMPTY_PIN_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 Empty PIN Token Store Test ===\n");

    (void)empty_pin_store_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
#else
    (void)argc;
    (void)argv;
    printf("KeyStore not compiled in (WOLFPKCS11_NO_STORE defined)!\n");
    return 77;
#endif
}
