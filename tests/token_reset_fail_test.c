/* token_reset_fail_test.c
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
 * Checks that C_InitToken reports a token initialization failure, leaves the
 * token unprovisioned and lets a later C_InitToken succeed without leaking.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/token_reset_fail_test"

#ifdef DEBUG_WOLFPKCS11

extern void WP11_Test_FailTokenInit(int fail);

static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";

static long liveBlocks = 0;

static void* count_malloc(size_t sz)
{
    void* p = malloc(sz);

    if (p != NULL)
        liveBlocks++;
    return p;
}

static void count_free(void* ptr)
{
    if (ptr != NULL)
        liveBlocks--;
    free(ptr);
}

static void* count_realloc(void* ptr, size_t sz)
{
    void* np = realloc(ptr, sz);

    if (ptr == NULL && np != NULL)
        liveBlocks++;
    return np;
}

static CK_RV init_token(CK_SLOT_ID slot)
{
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "reset-fail", 10);
    return funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                 (CK_ULONG)XSTRLEN(soPin), label);
}

/* Provision the token and log the user in on a fresh session. */
static CK_RV provision_and_login(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
    }
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    return rv;
}

static void token_reset_fail_test(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SLOT_ID slot = 0;
    CK_TOKEN_INFO info;
    long before;

    printf("--- token reset stops when token initialization fails ---\n");
    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_OK && slotCount == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    CHECK_RV(rv, "initialize and find a slot", CKR_OK);
    if (rv == CKR_OK) {
        slot = slotList[0];
        before = liveBlocks;
        WP11_Test_FailTokenInit(1);
        rv = init_token(slot);
        WP11_Test_FailTokenInit(0);
        CHECK_RV(rv, "C_InitToken with failing token initialization",
                 CKR_FUNCTION_FAILED);
        rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_RV(rv, "C_GetTokenInfo after the failure", CKR_OK);
        CHECK_TRUE(rv == CKR_OK && (info.flags & CKF_TOKEN_INITIALIZED) == 0,
                   "token not reported initialized");
        /* The old token state is released; the failed one allocates nothing. */
        if (liveBlocks > before) {
            fprintf(stderr, "  live blocks went from %ld to %ld\n", before,
                    liveBlocks);
        }
        CHECK_TRUE(liveBlocks <= before, "failed reset leaks nothing");
        rv = init_token(slot);
        CHECK_RV(rv, "C_InitToken again", CKR_OK);
        rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_TRUE(rv == CKR_OK && (info.flags & CKF_TOKEN_INITIALIZED) != 0,
                   "token reported initialized");
        rv = provision_and_login(slot);
        CHECK_RV(rv, "set the user PIN and log in", CKR_OK);
    }
    funcList->C_Finalize(NULL);
}

int main(int argc, char* argv[])
{
    CK_RV rv;

    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif
    if (wolfSSL_SetAllocators(count_malloc, count_free, count_realloc) != 0) {
        printf("Allocator hooks not available, skipping test\n");
        return 77;
    }

    printf("=== wolfPKCS11 token reset failure test ===\n");
    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv == CKR_OK)
        token_reset_fail_test();
    pkcs11_unload();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("Debug test hooks not built, skipping test\n");
    return 77;
}

#endif
