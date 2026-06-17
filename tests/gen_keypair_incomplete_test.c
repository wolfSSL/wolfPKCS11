/* gen_keypair_incomplete_test.c
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
 * Regression test for issue F-5518. C_GenerateKeyPair built the key objects
 * and ran the mechanism generator without first checking the mechanism's
 * required public-key template attributes, so a missing CKA_MODULUS_BITS
 * (RSA), CKA_EC_PARAMS (EC) or CKA_PRIME/CKA_BASE (DH) surfaced as
 * CKR_FUNCTION_FAILED instead of CKR_TEMPLATE_INCOMPLETE.
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

#define TEST_DIR "./store/gen_keypair_incomplete_test"

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

/* Generate a key pair with the supplied public template and report the rv.
 * A CK_FALSE CKA_PRIVATE on the private template keeps the objects public so
 * the call does not require C_Login. The result must be CKR_TEMPLATE_INCOMPLETE
 * when the public template is missing a mechanism-required attribute, or
 * CKR_MECHANISM_INVALID if the mechanism is not built in (treated as skip). */
static void check_incomplete(CK_SESSION_HANDLE session, CK_MECHANISM_TYPE mech,
                             CK_ATTRIBUTE* pubTmpl, CK_ULONG pubCnt,
                             const char* op)
{
    CK_RV rv;
    CK_MECHANISM mechanism;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_PRIVATE, &ckFalse, sizeof(ckFalse) },
    };
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;

    XMEMSET(&mechanism, 0, sizeof(mechanism));
    mechanism.mechanism = mech;

    rv = funcList->C_GenerateKeyPair(session, &mechanism, pubTmpl, pubCnt,
                                     privTmpl,
                                     sizeof(privTmpl) / sizeof(*privTmpl),
                                     &pub, &priv);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: %s (mechanism not supported)\n", op);
        test_passed++;
        return;
    }
    CHECK_RV(rv, op, CKR_TEMPLATE_INCOMPLETE);
    if (rv == CKR_OK) {
        funcList->C_DestroyObject(session, pub);
        funcList->C_DestroyObject(session, priv);
    }
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
    CK_BBOOL ckTrue = CK_TRUE;
    /* RSA public template missing CKA_MODULUS_BITS. */
    CK_ATTRIBUTE rsaPub[] = {
        { CKA_ENCRYPT, &ckTrue, sizeof(ckTrue) },
        { CKA_VERIFY,  &ckTrue, sizeof(ckTrue) },
    };
    /* EC public template missing CKA_EC_PARAMS. */
    CK_ATTRIBUTE ecPub[] = {
        { CKA_VERIFY,  &ckTrue, sizeof(ckTrue) },
    };
    /* DH public template missing CKA_PRIME and CKA_BASE. */
    CK_ATTRIBUTE dhPub[] = {
        { CKA_DERIVE,  &ckTrue, sizeof(ckTrue) },
    };

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

    check_incomplete(session, CKM_RSA_PKCS_KEY_PAIR_GEN, rsaPub,
                     sizeof(rsaPub) / sizeof(*rsaPub),
                     "RSA keygen without CKA_MODULUS_BITS");
    check_incomplete(session, CKM_EC_KEY_PAIR_GEN, ecPub,
                     sizeof(ecPub) / sizeof(*ecPub),
                     "EC keygen without CKA_EC_PARAMS");
    check_incomplete(session, CKM_DH_PKCS_KEY_PAIR_GEN, dhPub,
                     sizeof(dhPub) / sizeof(*dhPub),
                     "DH keygen without CKA_PRIME/CKA_BASE");

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

    printf("=== wolfPKCS11 C_GenerateKeyPair incomplete-template test ===\n");
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
