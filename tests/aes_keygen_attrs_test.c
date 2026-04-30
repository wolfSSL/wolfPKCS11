/* aes_keygen_attrs_test.c
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
 * Test that C_GenerateKey sets CKA_LOCAL and CKA_KEY_GEN_MECHANISM
 * correctly on generated symmetric keys (bugs #2033, #2034).
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

#ifndef NO_AES

#define TEST_DIR "./store/aes_keygen_attrs_test"
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

static void cleanup_test_files(const char* dir)
{
    char filepath[512];

    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", dir,
             WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

/*
 * Test: Generate an AES-256 key via C_GenerateKey and verify that
 * CKA_LOCAL is CK_TRUE and CKA_KEY_GEN_MECHANISM is CKM_AES_KEY_GEN.
 */
static int test_aes_keygen_attrs(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    CK_MECHANISM mech;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_ULONG keyLen = 32;
    CK_BBOOL local = CK_FALSE;
    CK_MECHANISM_TYPE genMech = CK_UNAVAILABLE_INFORMATION;
    int result = 0;

    CK_ATTRIBUTE genTmpl[] = {
        { CKA_VALUE_LEN, &keyLen,  sizeof(keyLen)  },
        { CKA_KEY_TYPE,  &keyType, sizeof(keyType)  },
    };
    CK_ULONG genTmplCnt = sizeof(genTmpl) / sizeof(*genTmpl);

    CK_ATTRIBUTE getTmpl[] = {
        { CKA_LOCAL,              &local,   sizeof(local)   },
        { CKA_KEY_GEN_MECHANISM,  &genMech, sizeof(genMech) },
    };
    CK_ULONG getTmplCnt = sizeof(getTmpl) / sizeof(*getTmpl);

    mech.mechanism      = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_GenerateKey(session, &mech, genTmpl, genTmplCnt, &key);
    CHECK_CKR(ret, "C_GenerateKey (AES-256)", CKR_OK);

    ret = funcList->C_GetAttributeValue(session, key, getTmpl, getTmplCnt);
    CHECK_CKR(ret, "C_GetAttributeValue (CKA_LOCAL, CKA_KEY_GEN_MECHANISM)",
              CKR_OK);

    if (local != CK_TRUE) {
        fprintf(stderr,
                "FAIL: CKA_LOCAL: expected CK_TRUE, got %d\n", (int)local);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: CKA_LOCAL is CK_TRUE\n");
    test_passed++;

    if (genMech != CKM_AES_KEY_GEN) {
        fprintf(stderr,
                "FAIL: CKA_KEY_GEN_MECHANISM: expected 0x%lx (CKM_AES_KEY_GEN),"
                " got 0x%lx\n",
                (unsigned long)CKM_AES_KEY_GEN, (unsigned long)genMech);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: CKA_KEY_GEN_MECHANISM is CKM_AES_KEY_GEN\n");
    test_passed++;

cleanup:
    return result;
}

static int aes_keygen_attrs_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int result = 0;

    printf("\n=== Testing C_GenerateKey CKA_LOCAL and CKA_KEY_GEN_MECHANISM ===\n");

    cleanup_test_files(TEST_DIR);

    ret = pkcs11_init();
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: pkcs11_init: 0x%lx\n", (unsigned long)ret);
        test_failed++;
        return -1;
    }

    ret = pkcs11_init_token();
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: C_InitToken: 0x%lx\n", (unsigned long)ret);
        test_failed++;
        pkcs11_final();
        return -1;
    }

    /* Set user PIN via SO session */
    {
        CK_SESSION_HANDLE soSession;
        int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

        ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &soSession);
        if (ret != CKR_OK) {
            fprintf(stderr, "FAIL: C_OpenSession (SO): 0x%lx\n",
                    (unsigned long)ret);
            test_failed++;
            pkcs11_final();
            return -1;
        }

        ret = funcList->C_Login(soSession, CKU_SO, soPin, soPinLen);
        if (ret != CKR_OK) {
            fprintf(stderr, "FAIL: C_Login (SO): 0x%lx\n",
                    (unsigned long)ret);
            test_failed++;
            funcList->C_CloseSession(soSession);
            pkcs11_final();
            return -1;
        }

        ret = funcList->C_InitPIN(soSession, userPin, userPinLen);
        if (ret != CKR_OK) {
            fprintf(stderr, "FAIL: C_InitPIN: 0x%lx\n", (unsigned long)ret);
            test_failed++;
            funcList->C_Logout(soSession);
            funcList->C_CloseSession(soSession);
            pkcs11_final();
            return -1;
        }

        funcList->C_Logout(soSession);
        funcList->C_CloseSession(soSession);
    }

    ret = pkcs11_open_session(&session);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: pkcs11_open_session: 0x%lx\n",
                (unsigned long)ret);
        test_failed++;
        pkcs11_final();
        return -1;
    }

    if (test_aes_keygen_attrs(session) != 0)
        result = -1;

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
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 AES KeyGen Attributes Test ===\n");

    (void)aes_keygen_attrs_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* NO_AES */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES not available, skipping keygen attributes test\n");
    return 0;
}

#endif /* !NO_AES */
