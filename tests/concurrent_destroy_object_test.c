/* concurrent_destroy_object_test.c
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
 * Regression test for the concurrent C_DestroyObject double-free / use-after-
 * free on a shared token object.
 *
 * A token object is visible to every session of an application, so two threads
 * using two different sessions may legitimately call C_DestroyObject on the
 * same object handle at the same time (a supported concurrent use under
 * CKF_OS_LOCKING_OK). The buggy code resolved the handle to a raw WP11_Object*
 * under a released read lock, so both callers reached WP11_Object_Free on the
 * same pointer - a double free - and the loser also dereferenced the freed
 * object inside WP11_Session_RemoveObjectByHandle.
 *
 * Each round below creates one token object and has two threads (each on its
 * own session) destroy it simultaneously. The fix must guarantee that exactly
 * one destroy returns CKR_OK, the other returns CKR_OBJECT_HANDLE_INVALID, and
 * the process does not corrupt the heap. Built with ASan this reliably aborts
 * on the unfixed library.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

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

#if !defined(NO_AES) && !defined(SINGLE_THREADED) && \
    !defined(WOLFPKCS11_SINGLE_THREADED)

#include <pthread.h>

#define CONCURRENT_DESTROY_TEST_DIR "./store/concurrent_destroy_object_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

#define DEFAULT_ROUNDS 250

static int test_passed = 0;
static int test_failed = 0;

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static const char* tokenName = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_KEY_TYPE aesKeyType = CKK_AES;

/* Rendezvous state shared between the main thread and the two destroyers.
 * A busy-wait ("spin") barrier is used deliberately: cond-var wakeups have
 * enough latency that one destroyer routinely finishes before the other
 * starts, which hides the race. Spinning releases both threads within a few
 * cycles of each other so their C_DestroyObject calls truly overlap. */
static volatile int g_go = 0;           /* bumped by main to release a round   */
static volatile int g_done = 0;         /* threads that finished current round */
static volatile int g_stop = 0;         /* set to make the threads exit        */
static CK_OBJECT_HANDLE g_target = CK_INVALID_HANDLE;
static CK_RV g_rv[2];                   /* per-thread result for the round     */

typedef struct {
    int id;
    CK_SESSION_HANDLE session;
} thread_ctx;

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

static void pkcs11_final(void)
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

    /* Login state is token-wide: only the first session needs to log the user
     * in, later sessions inherit it and report CKR_USER_ALREADY_LOGGED_IN. */
    ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    if (ret != CKR_OK && ret != CKR_USER_ALREADY_LOGGED_IN) {
        funcList->C_CloseSession(*session);
        return ret;
    }

    return CKR_OK;
}

static void cleanup_test_files(const char* dir)
{
    char filepath[512];

    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", dir,
             WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

/* Create an AES token secret key and return its handle. */
static CK_RV create_token_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_VALUE,    aes_128_key,     sizeof(aes_128_key)    },
        { CKA_TOKEN,    &ckTrue,         sizeof(ckTrue)         },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

/* Destroyer thread: each round, wait to be released, then destroy the shared
 * target handle at the same moment as the peer thread. */
static void* destroyer(void* arg)
{
    thread_ctx* ctx = (thread_ctx*)arg;
    int last = 0;

    for (;;) {
        CK_OBJECT_HANDLE h;

        /* Tight spin until main releases the next round (or asks us to stop). */
        while (g_go == last && !g_stop) { }
        if (g_stop)
            break;
        last = g_go;
        __sync_synchronize();       /* observe g_target published before g_go */
        h = g_target;

        g_rv[ctx->id] = funcList->C_DestroyObject(ctx->session, h);

        __sync_fetch_and_add(&g_done, 1);
    }

    return NULL;
}

static int concurrent_destroy_test(int rounds)
{
    CK_RV ret;
    CK_SESSION_HANDLE creator = 0;
    thread_ctx ctx[2];
    pthread_t threads[2];
    int result = 0;
    int r;
    int started = 0;

    printf("\n=== Testing concurrent C_DestroyObject on a shared token "
           "object (%d rounds) ===\n", rounds);

    cleanup_test_files(CONCURRENT_DESTROY_TEST_DIR);

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
        goto cleanup;
    }

    ret = pkcs11_set_user_pin();
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: set user PIN: 0x%lx\n", (unsigned long)ret);
        test_failed++;
        goto cleanup;
    }

    ret = pkcs11_open_session(&creator);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: open creator session: 0x%lx\n",
                (unsigned long)ret);
        test_failed++;
        goto cleanup;
    }

    for (r = 0; r < 2; r++) {
        ctx[r].id = r;
        ret = pkcs11_open_session(&ctx[r].session);
        if (ret != CKR_OK) {
            fprintf(stderr, "FAIL: open destroyer session %d: 0x%lx\n", r,
                    (unsigned long)ret);
            test_failed++;
            goto cleanup;
        }
        if (pthread_create(&threads[r], NULL, destroyer, &ctx[r]) != 0) {
            fprintf(stderr, "FAIL: pthread_create %d\n", r);
            test_failed++;
            goto cleanup;
        }
        started++;
    }

    for (r = 0; r < rounds; r++) {
        CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
        int oks;

        ret = create_token_key(creator, &h);
        if (ret != CKR_OK) {
            fprintf(stderr, "FAIL: create token key (round %d): 0x%lx\n", r,
                    (unsigned long)ret);
            test_failed++;
            result = -1;
            break;
        }

        /* Publish the handle, release both threads onto it simultaneously,
         * then spin until both have returned from C_DestroyObject. */
        g_target = h;
        g_rv[0] = g_rv[1] = CKR_GENERAL_ERROR;
        g_done = 0;
        __sync_synchronize();
        g_go = r + 1;
        while (g_done < 2) { }
        __sync_synchronize();

        /* Exactly one destroy must win; the other must report an invalid
         * handle. Any other combination (two successes, or a status other
         * than CKR_OBJECT_HANDLE_INVALID for the loser) is a defect. */
        oks = (g_rv[0] == CKR_OK) + (g_rv[1] == CKR_OK);
        if (oks != 1) {
            fprintf(stderr,
                "FAIL: round %d expected exactly one CKR_OK, got rv0=0x%lx "
                "rv1=0x%lx\n", r, (unsigned long)g_rv[0],
                (unsigned long)g_rv[1]);
            test_failed++;
            result = -1;
            break;
        }
        if (g_rv[0] != CKR_OK && g_rv[0] != CKR_OBJECT_HANDLE_INVALID) {
            fprintf(stderr, "FAIL: round %d loser rv0=0x%lx\n", r,
                    (unsigned long)g_rv[0]);
            test_failed++;
            result = -1;
            break;
        }
        if (g_rv[1] != CKR_OK && g_rv[1] != CKR_OBJECT_HANDLE_INVALID) {
            fprintf(stderr, "FAIL: round %d loser rv1=0x%lx\n", r,
                    (unsigned long)g_rv[1]);
            test_failed++;
            result = -1;
            break;
        }

        /* The object must really be gone: a follow-up destroy fails. */
        ret = funcList->C_DestroyObject(creator, h);
        if (ret != CKR_OBJECT_HANDLE_INVALID) {
            fprintf(stderr,
                "FAIL: round %d object still present after destroy: 0x%lx\n",
                r, (unsigned long)ret);
            test_failed++;
            result = -1;
            break;
        }
    }

    if (result == 0) {
        printf("PASS: %d concurrent-destroy rounds, one winner each, no "
               "double free\n", rounds);
        test_passed++;
    }

cleanup:
    /* Tell the destroyer threads to exit and join them. */
    g_stop = 1;
    __sync_synchronize();
    for (r = 0; r < started; r++)
        pthread_join(threads[r], NULL);
    for (r = 0; r < started; r++) {
        funcList->C_Logout(ctx[r].session);
        funcList->C_CloseSession(ctx[r].session);
    }

    if (creator != 0) {
        funcList->C_Logout(creator);
        funcList->C_CloseSession(creator);
    }
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
    int rounds = DEFAULT_ROUNDS;

    if (argc > 1) {
        int v = atoi(argv[1]);
        if (v > 0)
            rounds = v;
    }

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", CONCURRENT_DESTROY_TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 concurrent C_DestroyObject Test ===\n");

    (void)concurrent_destroy_test(rounds);

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* NO_AES || SINGLE_THREADED */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES or threading not available, skipping concurrent "
           "C_DestroyObject test\n");
    return 0;
}

#endif /* !NO_AES && !SINGLE_THREADED */
