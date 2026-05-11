/* so_login_uninit_test.c
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
 * Regression test for the SO PIN empty-PIN bypass that
 * WP11_Slot_CheckSOPin used to allow when the SO PIN had not been set.
 * Before the fix, C_Login(CKU_SO, "", 0) on a fresh (uninitialized) token
 * would succeed because WP11_ConstantCompare(., ., 0) returns true. This
 * test exercises that exact path and asserts the call now fails with
 * CKR_USER_PIN_NOT_INITIALIZED.
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

#define SO_TEST_DIR "./store/so_login_uninit_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

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

/* Empty-PIN may be rejected by C_Login's length check before reaching the
 * SO-PIN check, or by the fix in WP11_Slot_CheckSOPin. Either rejection
 * proves the bypass is closed. */
#define CHECK_EMPTY_REJECTED(rv, op) do {                                     \
    if ((rv) != CKR_USER_PIN_NOT_INITIALIZED &&                               \
        (rv) != CKR_PIN_INCORRECT &&                                          \
        (rv) != CKR_PIN_LEN_RANGE) {                                          \
        fprintf(stderr, "FAIL: %s: empty PIN accepted with 0x%lx\n", op,      \
                (unsigned long)(rv));                                         \
        test_failed++;                                                        \
    } else {                                                                  \
        printf("PASS: %s (rv=0x%lx)\n", op, (unsigned long)(rv));             \
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

static void cleanup_store(const char* dir)
{
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", dir,
             WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
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

    /* Drop any token file so the token loads in an uninitialized state
     * with WP11_TOKEN_FLAG_SO_PIN_SET clear. */
    cleanup_store(SO_TEST_DIR);

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
    CHECK_RV(rv, "C_OpenSession (uninit token)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

#ifndef WOLFPKCS11_NSS
    /* Non-NSS builds: empty PIN against unset SO PIN must be rejected;
     * pre-fix this succeeded because the zero-length constant-compare
     * returned equal. Builds with WP11_MIN_PIN_LEN > 0 reject the length
     * first; either rejection proves the bypass is closed. */
    rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)"", 0);
    CHECK_EMPTY_REJECTED(rv, "C_Login(CKU_SO, \"\", 0) rejected");
#else
    /* NSS builds intentionally accept the empty-PIN SO login on an
     * uninitialized token so NSS's PK11_InitPin can bootstrap. Just
     * verify that calling it does not return an error code that would
     * cause NSS to abort. */
    rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)"", 0);
    if (rv != CKR_OK) {
        fprintf(stderr,
                "FAIL: NSS empty-PIN probe expected CKR_OK, got 0x%lx\n",
                (unsigned long)rv);
        test_failed++;
    } else {
        printf("PASS: NSS empty-PIN probe succeeds (bootstrap path)\n");
        test_passed++;
        funcList->C_Logout(session);
    }
#endif

    /* Non-empty PIN against unset SO PIN: must report
     * CKR_USER_PIN_NOT_INITIALIZED rather than CKR_PIN_INCORRECT so the
     * caller can distinguish "wrong PIN" from "no PIN set". This must hold
     * in both NSS and non-NSS builds; the NSS empty-PIN bypass is
     * length-zero only. */
    rv = funcList->C_Login(session, CKU_SO,
                           (CK_UTF8CHAR_PTR)"longerbadpin", 12);
    CHECK_RV(rv, "C_Login(CKU_SO, non-empty, uninit) returns NOT_INITIALIZED",
             CKR_USER_PIN_NOT_INITIALIZED);

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
    XSETENV("WOLFPKCS11_TOKEN_PATH", SO_TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 SO PIN uninit bypass test ===\n");
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
