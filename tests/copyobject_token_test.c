/* copyobject_token_test.c
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
 * Test for C_CopyObject CKA_TOKEN inheritance (bug #4534).
 *
 * Per PKCS#11 v2.40 4.6.2, a copy's attributes equal the source's except where
 * the supplied template overrides them. CKA_TOKEN must therefore default to the
 * source object's CKA_TOKEN when the template omits it. The buggy code defaulted
 * the copy to a session object regardless of the source.
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

#if !defined(NO_AES)

#define COPY_TOKEN_TEST_DIR "./store/copyobject_token_test"
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

#define CHECK_COND(cond, op) do {                           \
    if (!(cond)) {                                          \
        fprintf(stderr, "FAIL: %s\n", op);                 \
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
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_KEY_TYPE aesKeyType = CKK_AES;

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

static CK_RV pkcs11_set_user_pin(void)
{
    CK_SESSION_HANDLE soSession;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_RV ret;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &soSession);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_Login(soSession, CKU_SO, soPin, soPinLen);
    if (ret != CKR_OK) {
        funcList->C_CloseSession(soSession);
        return ret;
    }

    ret = funcList->C_InitPIN(soSession, userPin, userPinLen);
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    return ret;
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

/* Create an AES secret key with the requested CKA_TOKEN value. */
static CK_RV create_aes_key(CK_SESSION_HANDLE session, CK_BBOOL onToken,
                            CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass,   sizeof(secretKeyClass)   },
        { CKA_KEY_TYPE,    &aesKeyType,       sizeof(aesKeyType)       },
        { CKA_ENCRYPT,     &ckTrue,           sizeof(ckTrue)           },
        { CKA_DECRYPT,     &ckTrue,           sizeof(ckTrue)           },
        { CKA_VALUE,       aes_128_key,       sizeof(aes_128_key)      },
        { CKA_TOKEN,       &onToken,          sizeof(onToken)          },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

/* Read CKA_TOKEN of an object. */
static CK_RV get_token_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                            CK_BBOOL* onToken)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, onToken, sizeof(*onToken) },
    };

    *onToken = 0xAA; /* sentinel so an untouched value is detectable */
    return funcList->C_GetAttributeValue(session, obj, tmpl, 1);
}

/*
 * Test 1: Copy a token object with an empty template. The copy must inherit
 * CKA_TOKEN=TRUE from the source. This is the reported bug.
 */
static int test_copy_token_inherits_true(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE src = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_BBOOL onToken = 0;
    int result = 0;

    ret = create_aes_key(session, CK_TRUE, &src);
    CHECK_CKR(ret, "Test1: create token source object", CKR_OK);

    ret = funcList->C_CopyObject(session, src, NULL, 0, &copy);
    CHECK_CKR(ret, "Test1: C_CopyObject empty template", CKR_OK);

    ret = get_token_attr(session, copy, &onToken);
    CHECK_CKR(ret, "Test1: C_GetAttributeValue CKA_TOKEN", CKR_OK);

    CHECK_COND(onToken == CK_TRUE,
               "Test1: copy of token object inherits CKA_TOKEN=TRUE");

cleanup:
    if (copy != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copy);
    if (src != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, src);
    return result;
}

/*
 * Test 2: Copy a token object but override CKA_TOKEN=FALSE in the template.
 * The copy must be a session object.
 */
static int test_copy_token_override_false(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE src = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_BBOOL onToken = 0;
    int result = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
    };

    ret = create_aes_key(session, CK_TRUE, &src);
    CHECK_CKR(ret, "Test2: create token source object", CKR_OK);

    ret = funcList->C_CopyObject(session, src, tmpl, 1, &copy);
    CHECK_CKR(ret, "Test2: C_CopyObject CKA_TOKEN=FALSE", CKR_OK);

    ret = get_token_attr(session, copy, &onToken);
    CHECK_CKR(ret, "Test2: C_GetAttributeValue CKA_TOKEN", CKR_OK);

    CHECK_COND(onToken == CK_FALSE,
               "Test2: template override CKA_TOKEN=FALSE honored");

cleanup:
    if (copy != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copy);
    if (src != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, src);
    return result;
}

/*
 * Test 3: Copy a session object with an empty template. The copy must remain a
 * session object (inherit CKA_TOKEN=FALSE).
 */
static int test_copy_session_inherits_false(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE src = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_BBOOL onToken = 0;
    int result = 0;

    ret = create_aes_key(session, CK_FALSE, &src);
    CHECK_CKR(ret, "Test3: create session source object", CKR_OK);

    ret = funcList->C_CopyObject(session, src, NULL, 0, &copy);
    CHECK_CKR(ret, "Test3: C_CopyObject empty template", CKR_OK);

    ret = get_token_attr(session, copy, &onToken);
    CHECK_CKR(ret, "Test3: C_GetAttributeValue CKA_TOKEN", CKR_OK);

    CHECK_COND(onToken == CK_FALSE,
               "Test3: copy of session object inherits CKA_TOKEN=FALSE");

cleanup:
    if (copy != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copy);
    if (src != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, src);
    return result;
}

/*
 * Test 4: Copy a session object but override CKA_TOKEN=TRUE in the template.
 * The copy must become a token object.
 */
static int test_copy_session_override_true(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE src = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_BBOOL onToken = 0;
    int result = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
    };

    ret = create_aes_key(session, CK_FALSE, &src);
    CHECK_CKR(ret, "Test4: create session source object", CKR_OK);

    ret = funcList->C_CopyObject(session, src, tmpl, 1, &copy);
    CHECK_CKR(ret, "Test4: C_CopyObject CKA_TOKEN=TRUE", CKR_OK);

    ret = get_token_attr(session, copy, &onToken);
    CHECK_CKR(ret, "Test4: C_GetAttributeValue CKA_TOKEN", CKR_OK);

    CHECK_COND(onToken == CK_TRUE,
               "Test4: template override CKA_TOKEN=TRUE honored");

cleanup:
    if (copy != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copy);
    if (src != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, src);
    return result;
}

/*
 * Test 5: A token object copy (empty template) must be discoverable by a
 * C_FindObjects search restricted to token objects.
 */
static int test_copy_token_findable(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE src = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE found[8];
    CK_ULONG foundCount = 0;
    CK_ULONG i;
    int sawCopy = 0;
    int result = 0;
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
    };

    ret = create_aes_key(session, CK_TRUE, &src);
    CHECK_CKR(ret, "Test5: create token source object", CKR_OK);

    ret = funcList->C_CopyObject(session, src, NULL, 0, &copy);
    CHECK_CKR(ret, "Test5: C_CopyObject empty template", CKR_OK);

    ret = funcList->C_FindObjectsInit(session, findTmpl, 1);
    CHECK_CKR(ret, "Test5: C_FindObjectsInit token filter", CKR_OK);

    ret = funcList->C_FindObjects(session, found,
                                  sizeof(found) / sizeof(found[0]), &foundCount);
    CHECK_CKR(ret, "Test5: C_FindObjects", CKR_OK);

    ret = funcList->C_FindObjectsFinal(session);
    CHECK_CKR(ret, "Test5: C_FindObjectsFinal", CKR_OK);

    for (i = 0; i < foundCount; i++) {
        if (found[i] == copy)
            sawCopy = 1;
    }
    CHECK_COND(sawCopy,
               "Test5: token-object copy found via CKA_TOKEN=TRUE search");

cleanup:
    if (copy != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copy);
    if (src != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, src);
    return result;
}

static int copyobject_token_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int result = 0;

    printf("\n=== Testing C_CopyObject CKA_TOKEN inheritance ===\n");

    cleanup_test_files(COPY_TOKEN_TEST_DIR);

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

    ret = pkcs11_set_user_pin();
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: set user PIN: 0x%lx\n", (unsigned long)ret);
        test_failed++;
        pkcs11_final();
        return -1;
    }

    ret = pkcs11_open_session(&session);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: pkcs11_open_session: 0x%lx\n",
                (unsigned long)ret);
        test_failed++;
        pkcs11_final();
        return -1;
    }

    if (test_copy_token_inherits_true(session) != 0)
        result = -1;
    if (test_copy_token_override_false(session) != 0)
        result = -1;
    if (test_copy_session_inherits_false(session) != 0)
        result = -1;
    if (test_copy_session_override_true(session) != 0)
        result = -1;
    if (test_copy_token_findable(session) != 0)
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

    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");
}

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", COPY_TOKEN_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 C_CopyObject CKA_TOKEN Test ===\n");

    (void)copyobject_token_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* NO_AES */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES not available, skipping C_CopyObject CKA_TOKEN test\n");
    return 0;
}

#endif /* !NO_AES */
