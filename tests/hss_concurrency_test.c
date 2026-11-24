/* hss_concurrency_test.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * Threads sign with one shared HSS key (--enable-lms-private); every signature
 * must use a distinct leaf index, with no gaps, and verify.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

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

#include <stdio.h>
#include <string.h>

#if defined(WOLFPKCS11_LMS_PRIVATE) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_TPM_STORE) && \
    !defined(SINGLE_THREADED) && !defined(WOLFPKCS11_SINGLE_THREADED) && \
    !defined(_WIN32)

#include <pthread.h>
#include <stdlib.h>
#include <dirent.h>

#ifndef WOLFPKCS11_DLL_FILENAME
    #ifdef __MACH__
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.dylib"
    #else
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.so"
    #endif
#endif

/* H10 = 1024-leaf tree; NUM_THREADS*SIGS_PER_THREAD stays well under it so the
 * test exercises contention without hitting the exhaustion boundary. */
#define NUM_THREADS       4
#define SIGS_PER_THREAD   64
#define TOTAL_SIGS        (NUM_THREADS * SIGS_PER_THREAD)
#define MAX_SIG_LEN       8192

#define CHECK_CKR(rv, msg)                                                 \
    do {                                                                   \
        if ((rv) != CKR_OK) {                                             \
            fprintf(stderr, "\n%s:%d - %s: %lx - FAIL\n",                  \
                    __FILE__, __LINE__, msg, (unsigned long)(rv));         \
        }                                                                  \
    }                                                                      \
    while (0)

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
static const char* storeDir = "./store/hss_conc";

static CK_BBOOL ckTrue = CK_TRUE;
static CK_ULONG hssLevels = 1;
static CK_ULONG hssLmsType = CKL_LMS_SHA256_M32_H10;
static CK_ULONG hssLmotsType = CKL_LMOTS_SHA256_N32_W4;
static CK_BYTE keyId[] = "hss-concurrency";
static const CK_BYTE testMsg[] = "wolfPKCS11 HSS concurrency test message";
#define TEST_MSG_LEN ((CK_ULONG)(sizeof(testMsg) - 1))

/* Per-thread context: the leaf indices this thread observed. */
typedef struct {
    int threadId;
    word32 leaf[SIGS_PER_THREAD];
    int signedCount;
    CK_RV err;
} WorkerCtx;

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
        return CKR_GENERAL_ERROR;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
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

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    CHECK_CKR(ret, "Initialize");
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
        CHECK_CKR(ret, "Get Slot List");
    }
    if (ret == CKR_OK) {
        if (slotCount > 0)
            slot = slotList[0];
        else
            ret = CKR_GENERAL_ERROR;
    }
    return ret;
}

static void pkcs11_final(void)
{
    funcList->C_Finalize(NULL);
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
}

static CK_RV pkcs11_init_token(void)
{
    CK_RV ret;
    unsigned char label[32];
    CK_SESSION_HANDLE session;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, strlen(tokenName));
    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    CHECK_CKR(ret, "Init Token");
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
        CHECK_CKR(ret, "Open Session for PIN setup");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Login SO");
        if (ret == CKR_OK) {
            ret = funcList->C_InitPIN(session, userPin, userPinLen);
            CHECK_CKR(ret, "Init User PIN");
        }
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    return ret;
}

/* Open a logged-in session; CKR_USER_ALREADY_LOGGED_IN counts as success. */
static CK_RV open_logged_in_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    if (ret != CKR_OK)
        return ret;
    ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    if (ret == CKR_USER_ALREADY_LOGGED_IN)
        ret = CKR_OK;
    return ret;
}

static CK_RV gen_hss_key(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_VERIFY,         &ckTrue,       sizeof(ckTrue)       },
        { CKA_ID,             keyId,         sizeof(keyId) - 1    },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_SIGN,  &ckTrue, sizeof(ckTrue) },
        { CKA_ID,    keyId,   sizeof(keyId) - 1 },
        { CKA_HSS_LEVELS,      &hssLevels, sizeof(hssLevels) },
        { CKA_HSS_LMS_TYPES,   &hssLmsType, sizeof(hssLmsType) },
        { CKA_HSS_LMOTS_TYPES, &hssLmotsType, sizeof(hssLmotsType) },
    };

    mech.mechanism = CKM_HSS_KEY_PAIR_GEN;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    ret = funcList->C_GenerateKeyPair(session, &mech,
        pubTmpl, sizeof(pubTmpl) / sizeof(*pubTmpl),
        privTmpl, sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
    CHECK_CKR(ret, "C_GenerateKeyPair(HSS L1/H10)");
    return ret;
}

static CK_RV find_by_id(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls,
    CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,  sizeof(cls)        },
        { CKA_ID,    keyId, sizeof(keyId) - 1  },
    };

    ret = funcList->C_FindObjectsInit(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl));
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, obj, 1, &count);
        funcList->C_FindObjectsFinal(session);
    }
    if (ret == CKR_OK && count != 1)
        ret = CKR_GENERAL_ERROR;
    return ret;
}

/* Big-endian u32 read. */
static word32 read_be32(const CK_BYTE* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16) |
           ((word32)p[2] << 8)  |  (word32)p[3];
}

/* Extract the LMS leaf index q from an HSS L1 signature. Returns 0 on success
 * and sets *q; non-zero if the signature is too short or not single-level. */
static int hss_leaf_index(const CK_BYTE* sig, CK_ULONG sigLen, word32* q)
{
    word32 nspk;

    if (sigLen < 8)
        return -1;
    nspk = read_be32(sig);      /* HSS Nspk = L-1; must be 0 for L1 */
    if (nspk != 0)
        return -1;
    *q = read_be32(sig + 4);    /* first field of the LMS signature */
    return 0;
}

static void* worker(void* arg)
{
    WorkerCtx* ctx = (WorkerCtx*)arg;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE, pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_BYTE sig[MAX_SIG_LEN];
    CK_ULONG sigLen;
    CK_RV ret;
    int i;

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = open_logged_in_session(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, &priv);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, &pub);

    for (i = 0; ret == CKR_OK && i < SIGS_PER_THREAD; i++) {
        ret = funcList->C_SignInit(session, &mech, priv);
        if (ret != CKR_OK)
            break;
        sigLen = sizeof(sig);
        ret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &sigLen);
        if (ret != CKR_OK)
            break;
        /* Verify and record the leaf index. */
        ret = funcList->C_VerifyInit(session, &mech, pub);
        if (ret == CKR_OK) {
            ret = funcList->C_Verify(session, (CK_BYTE*)testMsg, TEST_MSG_LEN,
                sig, sigLen);
        }
        if (ret != CKR_OK)
            break;
        if (hss_leaf_index(sig, sigLen, &ctx->leaf[i]) != 0) {
            ret = CKR_GENERAL_ERROR;
            break;
        }
        ctx->signedCount++;
    }

    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    ctx->err = ret;
    return NULL;
}

#define READS            256

/* Reads CKA_HSS_KEYS_REMAINING, which never goes up, and CKA_SIGN while the
 * workers sign. */
static void* reader(void* arg)
{
    CK_RV* err = (CK_RV*)arg;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ULONG last = (CK_ULONG)-1;
    CK_ULONG cur = 0;
    CK_BBOOL sign = CK_FALSE;
    CK_ATTRIBUTE a;
    CK_RV ret;
    int i;

    ret = open_logged_in_session(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, &priv);
    for (i = 0; ret == CKR_OK && i < READS; i++) {
        a.type = CKA_HSS_KEYS_REMAINING;
        a.pValue = &cur;
        a.ulValueLen = sizeof(cur);
        ret = funcList->C_GetAttributeValue(session, priv, &a, 1);
        if (ret == CKR_OK && cur > last)
            ret = CKR_GENERAL_ERROR;
        last = cur;
        if (ret == CKR_OK) {
            a.type = CKA_SIGN;
            a.pValue = &sign;
            a.ulValueLen = sizeof(sign);
            ret = funcList->C_GetAttributeValue(session, priv, &a, 1);
        }
        if (ret == CKR_OK && sign != CK_TRUE)
            ret = CKR_GENERAL_ERROR;
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    *err = ret;
    return NULL;
}

static CK_RV get_keys_remaining(CK_SESSION_HANDLE session, CK_ULONG* remaining)
{
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ATTRIBUTE a;

    ret = find_by_id(session, CKO_PRIVATE_KEY, &priv);
    if (ret == CKR_OK) {
        a.type = CKA_HSS_KEYS_REMAINING;
        a.pValue = remaining;
        a.ulValueLen = sizeof(*remaining);
        ret = funcList->C_GetAttributeValue(session, priv, &a, 1);
    }
    return ret;
}

static int cmp_word32(const void* a, const void* b)
{
    word32 x = *(const word32*)a;
    word32 y = *(const word32*)b;

    if (x < y)
        return -1;
    if (x > y)
        return 1;
    return 0;
}

static void cleanup_store(void)
{
    DIR* d;
    struct dirent* e;
    char path[512];

    d = opendir(storeDir);
    if (d == NULL)
        return;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "wp11_", 5) == 0) {
            snprintf(path, sizeof(path), "%s/%s", storeDir, e->d_name);
            (void)remove(path);
        }
    }
    closedir(d);
}

static CK_RV run_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE keeper = CK_INVALID_HANDLE;
    pthread_t threads[NUM_THREADS];
    pthread_t readerThread;
    CK_RV readerErr = CKR_OK;
    int readerStarted = 0;
    WorkerCtx ctx[NUM_THREADS];
    word32 allLeaves[TOTAL_SIGS];
    CK_ULONG remainBefore = 0, remainAfter = 0;
    int i, j, n = 0;
    int spawned = 0;

    XMEMSET(ctx, 0, sizeof(ctx));

    cleanup_store();
    ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = pkcs11_init_token();
    /* Keeper session keeps the token logged in for the workers. */
    if (ret == CKR_OK)
        ret = open_logged_in_session(&keeper);
    if (ret == CKR_OK)
        ret = gen_hss_key(keeper);
    if (ret == CKR_OK)
        ret = get_keys_remaining(keeper, &remainBefore);

    /* Fan out. */
    if (ret == CKR_OK) {
        if (pthread_create(&readerThread, NULL, reader, &readerErr) != 0)
            ret = CKR_GENERAL_ERROR;
        else
            readerStarted = 1;
    }
    for (i = 0; ret == CKR_OK && i < NUM_THREADS; i++) {
        ctx[i].threadId = i;
        ctx[i].err = CKR_OK;
        if (pthread_create(&threads[i], NULL, worker, &ctx[i]) != 0) {
            ret = CKR_GENERAL_ERROR;
            break;
        }
        spawned++;
    }
    for (i = 0; i < spawned; i++)
        pthread_join(threads[i], NULL);
    if (readerStarted) {
        pthread_join(readerThread, NULL);
        if (ret == CKR_OK && readerErr != CKR_OK) {
            fprintf(stderr, "\nkeys-remaining reader failed: %lx - FAIL\n",
                (unsigned long)readerErr);
            ret = readerErr;
        }
    }

    /* Collect results. */
    for (i = 0; ret == CKR_OK && i < NUM_THREADS; i++) {
        if (ctx[i].err != CKR_OK) {
            fprintf(stderr, "\nthread %d failed: %lx - FAIL\n", i,
                (unsigned long)ctx[i].err);
            ret = ctx[i].err;
        }
        else if (ctx[i].signedCount != SIGS_PER_THREAD) {
            fprintf(stderr, "\nthread %d signed %d/%d - FAIL\n", i,
                ctx[i].signedCount, SIGS_PER_THREAD);
            ret = CKR_GENERAL_ERROR;
        }
        else {
            for (j = 0; j < SIGS_PER_THREAD; j++)
                allLeaves[n++] = ctx[i].leaf[j];
        }
    }

    /* The N*M signatures must use leaf indices {0, 1, ..., N*M-1} exactly -
     * any duplicate is an OTS reuse, any gap is a lost index. */
    if (ret == CKR_OK) {
        qsort(allLeaves, TOTAL_SIGS, sizeof(word32), cmp_word32);
        for (i = 0; i < TOTAL_SIGS; i++) {
            if (allLeaves[i] != (word32)i) {
                if (i > 0 && allLeaves[i] == allLeaves[i - 1]) {
                    fprintf(stderr, "\nOTS INDEX REUSED: leaf %lu appears "
                        "twice - FAIL\n", (unsigned long)allLeaves[i]);
                }
                else {
                    fprintf(stderr, "\nleaf index sequence broken at %d: got "
                        "%lu - FAIL\n", i, (unsigned long)allLeaves[i]);
                }
                ret = CKR_GENERAL_ERROR;
                break;
            }
        }
    }

    /* Keys-remaining must have dropped by exactly TOTAL_SIGS. */
    if (ret == CKR_OK)
        ret = get_keys_remaining(keeper, &remainAfter);
    if (ret == CKR_OK && remainAfter != remainBefore - TOTAL_SIGS) {
        fprintf(stderr, "\nkeys-remaining %lu -> %lu, expected drop of %d "
            "- FAIL\n", (unsigned long)remainBefore,
            (unsigned long)remainAfter, TOTAL_SIGS);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        printf("  %d threads x %d signatures = %d unique leaf indices, all "
            "verified\n", NUM_THREADS, SIGS_PER_THREAD, TOTAL_SIGS);
    }

    if (keeper != CK_INVALID_HANDLE) {
        funcList->C_Logout(keeper);
        funcList->C_CloseSession(keeper);
    }
    pkcs11_final();
    return ret;
}
#endif /* LMS_PRIVATE && file store && !SINGLE_THREADED && !_WIN32 */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
#if defined(WOLFPKCS11_LMS_PRIVATE) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_TPM_STORE) && \
    !defined(SINGLE_THREADED) && !defined(WOLFPKCS11_SINGLE_THREADED) && \
    !defined(_WIN32)
    {
        CK_RV ret;

#ifndef WOLFPKCS11_NO_ENV
        XSETENV("WOLFPKCS11_TOKEN_PATH", storeDir, 1);
#endif

        printf("wolfPKCS11 HSS concurrent-signing (OTS reuse) test\n");
        printf("=================================================\n\n");

        ret = run_test();

        cleanup_store();
        if (ret == CKR_OK) {
            printf("\nAll tests passed!\n");
            return 0;
        }
        printf("\nTest failed with error: %lx\n", (unsigned long)ret);
        return 1;
    }
#else
    printf("LMS/HSS sign, store, and threads required - skipping.\n");
    return 77;
#endif
}
