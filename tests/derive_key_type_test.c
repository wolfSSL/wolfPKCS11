/* derive_key_type_test.c
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
 * Regression test for issue F-4065. C_DeriveKey passed the base key to the
 * mechanism-specific derive routine without checking that its key type
 * matched the mechanism, so a wrong base key type failed deep in the crypto
 * with CKR_FUNCTION_FAILED instead of the spec-mandated
 * CKR_KEY_TYPE_INCONSISTENT.
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

#define TEST_DIR "./store/derive_key_type_test"

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

/* Derive with the given mechanism using the wrong-typed base key and assert
 * CKR_KEY_TYPE_INCONSISTENT, or skip if the mechanism is not built in. */
static void check_wrong_type(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                             CK_OBJECT_HANDLE base, const char* op)
{
    CK_RV rv;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    CK_ULONG valLen = 16;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE outTmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_VALUE_LEN, &valLen,      sizeof(valLen)      },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
    };
    CK_OBJECT_HANDLE out = CK_INVALID_HANDLE;

    rv = funcList->C_DeriveKey(session, mech, base, outTmpl,
                               sizeof(outTmpl) / sizeof(*outTmpl), &out);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: %s (mechanism not supported)\n", op);
        test_passed++;
        return;
    }
    CHECK_RV(rv, op, CKR_KEY_TYPE_INCONSISTENT);
    if (rv == CKR_OK && out != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, out);
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
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_MECHANISM mech;
    byte pub[65];
    byte param[32];
    CK_ECDH1_DERIVE_PARAMS ecdh;
    /* An AES key is the wrong base-key type for every asymmetric/KDF derive
     * mechanism below. CKA_DERIVE=TRUE so the usage gate is passed and the
     * per-mechanism type check is the thing under test. */
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aes_128_key,  sizeof(aes_128_key) },
        { CKA_DERIVE,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ULONG aesTmplCnt = sizeof(aesTmpl) / sizeof(*aesTmpl);

    XMEMSET(pub, 4, sizeof(pub));
    XMEMSET(param, 7, sizeof(param));

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

    rv = funcList->C_CreateObject(session, aesTmpl, aesTmplCnt, &aesKey);
    CHECK_RV(rv, "C_CreateObject(AES base key)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    /* ECDH derive expects a CKK_EC base key. */
    XMEMSET(&ecdh, 0, sizeof(ecdh));
    ecdh.kdf = CKD_NULL;
    ecdh.pPublicData = pub;
    ecdh.ulPublicDataLen = sizeof(pub);
    mech.mechanism = CKM_ECDH1_DERIVE;
    mech.pParameter = &ecdh;
    mech.ulParameterLen = sizeof(ecdh);
    check_wrong_type(session, &mech, aesKey, "ECDH1 derive with AES base key");

    /* DH derive expects a CKK_DH base key. */
    mech.mechanism = CKM_DH_PKCS_DERIVE;
    mech.pParameter = param;
    mech.ulParameterLen = sizeof(param);
    check_wrong_type(session, &mech, aesKey, "DH derive with AES base key");

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

    printf("=== wolfPKCS11 C_DeriveKey base-key-type test ===\n");
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
