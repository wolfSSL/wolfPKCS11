/* pkcs11_compliance_test.c
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
 * Regression tests for PKCS#11 spec compliance fixes.
 * Each test covers a single Fenrir finding from the Tier 1 batch.
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

#define COMPLIANCE_TEST_DIR "./store/pkcs11_compliance_test"
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

#define CHECK_COND_MSG(cond, op) do {                                         \
    if (!(cond)) {                                                            \
        fprintf(stderr, "FAIL: %s\n", op);                                    \
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

static CK_RV lib_init(void)
{
    CK_C_INITIALIZE_ARGS args;
    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    return funcList->C_Initialize(&args);
}

static void cleanup_store(void)
{
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s",
             COMPLIANCE_TEST_DIR, WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

/* Finding 3399: C_GetSlotList must set *pulCount on CKR_BUFFER_TOO_SMALL so
 * the caller can resize and retry. */
static void test_3399_get_slot_list_buffer_too_small(void)
{
    CK_RV rv;
    CK_ULONG required = 0;
    CK_ULONG count;
    CK_SLOT_ID buf[1];

    printf("\n--- 3399: C_GetSlotList sets *count on BUFFER_TOO_SMALL ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    /* Discover number of slots via NULL query. */
    rv = funcList->C_GetSlotList(CK_FALSE, NULL, &required);
    CHECK_RV(rv, "C_GetSlotList(NULL) discovers count", CKR_OK);

    if (required == 0) {
        printf("SKIP: build exposes zero slots; cannot undersize\n");
        funcList->C_Finalize(NULL);
        return;
    }

    /* Ask with a too-small buffer (count=0, but slotIdList non-NULL); the spec
     * requires *count be updated to the required size on the
     * BUFFER_TOO_SMALL path so callers can resize and retry. */
    count = 0;
    rv = funcList->C_GetSlotList(CK_FALSE, buf, &count);
    CHECK_RV(rv, "C_GetSlotList undersized returns BUFFER_TOO_SMALL",
             CKR_BUFFER_TOO_SMALL);
    CHECK_COND_MSG(count == required,
                   "*count updated to required size on BUFFER_TOO_SMALL");

    funcList->C_Finalize(NULL);
}

/* Finding 1337: C_Finalize must return CKR_CRYPTOKI_NOT_INITIALIZED when the
 * library has not been initialized. */
static void test_1337_finalize_before_init(void)
{
    CK_RV rv;

    printf("\n--- 1337: C_Finalize before init returns NOT_INITIALIZED ---\n");

    /* Library is freshly loaded but not initialized. */
    rv = funcList->C_Finalize(NULL);
    CHECK_RV(rv, "C_Finalize before C_Initialize", CKR_CRYPTOKI_NOT_INITIALIZED);
}

/* Dummy mutex callbacks: must be present so the test never actually runs
 * them. The test only checks that C_Initialize rejects partial sets. */
static CK_RV dummy_create_mutex(CK_VOID_PTR_PTR ppMutex)
{ (void)ppMutex; return CKR_OK; }
static CK_RV dummy_destroy_mutex(CK_VOID_PTR pMutex)
{ (void)pMutex; return CKR_OK; }
static CK_RV dummy_lock_mutex(CK_VOID_PTR pMutex)
{ (void)pMutex; return CKR_OK; }
static CK_RV dummy_unlock_mutex(CK_VOID_PTR pMutex)
{ (void)pMutex; return CKR_OK; }

/* Finding 3140: C_Initialize must reject CK_C_INITIALIZE_ARGS that has some
 * (but not all) of the four mutex callback pointers populated. */
static void test_3140_initialize_partial_mutex_callbacks(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;

    printf("\n--- 3140: C_Initialize validates mutex callbacks ---\n");

    /* Three callbacks set, UnlockMutex NULL - must be rejected. */
    XMEMSET(&args, 0, sizeof(args));
    args.CreateMutex = dummy_create_mutex;
    args.DestroyMutex = dummy_destroy_mutex;
    args.LockMutex = dummy_lock_mutex;
    args.UnlockMutex = NULL;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "C_Initialize with partial mutex callbacks",
             CKR_ARGUMENTS_BAD);
    if (rv == CKR_OK)
        funcList->C_Finalize(NULL);

    /* All four callbacks set - must be accepted. */
    XMEMSET(&args, 0, sizeof(args));
    args.CreateMutex = dummy_create_mutex;
    args.DestroyMutex = dummy_destroy_mutex;
    args.LockMutex = dummy_lock_mutex;
    args.UnlockMutex = dummy_unlock_mutex;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "C_Initialize with full mutex callbacks", CKR_OK);
    if (rv == CKR_OK)
        funcList->C_Finalize(NULL);

    /* All four NULL with CKF_OS_LOCKING_OK - accepted (use library mutexes). */
    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "C_Initialize with no callbacks + CKF_OS_LOCKING_OK",
             CKR_OK);
    if (rv == CKR_OK)
        funcList->C_Finalize(NULL);

    /* Non-NULL pReserved must be rejected per spec. */
    {
        int reserved = 1;
        XMEMSET(&args, 0, sizeof(args));
        args.flags = CKF_OS_LOCKING_OK;
        args.pReserved = &reserved;
        rv = funcList->C_Initialize(&args);
        CHECK_RV(rv, "C_Initialize with non-NULL pReserved",
                 CKR_ARGUMENTS_BAD);
        if (rv == CKR_OK)
            funcList->C_Finalize(NULL);
    }
}

/* Open a session on slot 0 with the requested flags. Uses the standard
 * two-call slot-list pattern so a future module exposing many slots does not
 * trip an undersized buffer. Caller is responsible for closing. */
static CK_RV open_session(CK_FLAGS flags, CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_SLOT_ID firstSlot;
    CK_SLOT_ID* slotList = NULL;
    CK_ULONG slotCount = 0;

    rv = funcList->C_GetSlotList(CK_TRUE, NULL, &slotCount);
    if (rv != CKR_OK)
        return rv;
    if (slotCount == 0)
        return CKR_FUNCTION_FAILED;

    slotList = (CK_SLOT_ID*)XMALLOC(slotCount * sizeof(CK_SLOT_ID), NULL,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (slotList == NULL)
        return CKR_HOST_MEMORY;

    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_OK)
        firstSlot = slotList[0];
    XFREE(slotList, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (rv != CKR_OK)
        return rv;

    return funcList->C_OpenSession(firstSlot, flags, NULL, NULL, session);
}

static CK_RV open_ro_session(CK_SESSION_HANDLE* session)
{
    return open_session(CKF_SERIAL_SESSION, session);
}

/* Finding 1338: C_GenerateKey and C_GenerateKeyPair must enforce R/W when the
 * template marks the new key as a token object (CKA_TOKEN=TRUE). Either
 * template asking for a token object is enough — a private-only token must
 * not slip through when the public template requests CKA_TOKEN=FALSE.
 * Negative tests assert the rejection; positive tests assert session-only
 * keys still work on a R/O session so the gate does not over-fire. */
static void test_1338_generate_key_rw_session(void)
{
#ifdef WOLFPKCS11_NSS
    printf("\n--- 1338: C_GenerateKey/Pair enforce R/W for token keys ---\n");
    printf("SKIP: NSS builds intentionally treat all sessions as R/W\n");
#else
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privKey = CK_INVALID_HANDLE;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ULONG keyLen = 16;
    CK_MECHANISM mech;
    CK_ATTRIBUTE tplTokenTrue[] = {
        { CKA_TOKEN,     &ckTrue,  sizeof(ckTrue)  },
        { CKA_VALUE_LEN, &keyLen,  sizeof(keyLen)  },
    };
    CK_ATTRIBUTE tplSessionOnly[] = {
        { CKA_TOKEN,     &ckFalse, sizeof(ckFalse) },
        { CKA_VALUE_LEN, &keyLen,  sizeof(keyLen)  },
    };
    CK_MECHANISM kpMech;
    CK_ATTRIBUTE pubTokenTrue[] = {
        { CKA_TOKEN, &ckTrue,  sizeof(ckTrue)  },
    };
    CK_ATTRIBUTE privTokenTrue[] = {
        { CKA_TOKEN, &ckTrue,  sizeof(ckTrue)  },
    };
    CK_ATTRIBUTE pubTokenFalse[] = {
        { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
    };
    /* Public CKA_TOKEN=FALSE + private CKA_TOKEN=TRUE: this combination
     * exposes a public-template-only check, since the private template still
     * asks for a token object. */
    CK_ATTRIBUTE privOnlyToken[] = {
        { CKA_TOKEN, &ckTrue,  sizeof(ckTrue)  },
    };

    printf("\n--- 1338: C_GenerateKey/Pair enforce R/W for token keys ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = open_ro_session(&session);
    CHECK_RV(rv, "open R/O session", CKR_OK);
    if (rv != CKR_OK) goto out;

    /* Negative: CKA_TOKEN=TRUE must be rejected on R/O. */
    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_AES_KEY_GEN;
    rv = funcList->C_GenerateKey(session, &mech, tplTokenTrue,
                                 sizeof(tplTokenTrue) / sizeof(tplTokenTrue[0]),
                                 &key);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: CKM_AES_KEY_GEN not enabled\n");
    } else {
        CHECK_RV(rv, "C_GenerateKey(token=TRUE) on R/O session",
                 CKR_SESSION_READ_ONLY);
        if (rv == CKR_OK && key != CK_INVALID_HANDLE)
            funcList->C_DestroyObject(session, key);

        /* Positive: CKA_TOKEN=FALSE must succeed on R/O — the gate should
         * only require R/W for token objects. */
        key = CK_INVALID_HANDLE;
        rv = funcList->C_GenerateKey(session, &mech, tplSessionOnly,
                                     sizeof(tplSessionOnly) /
                                         sizeof(tplSessionOnly[0]),
                                     &key);
        CHECK_RV(rv, "C_GenerateKey(token=FALSE) on R/O session", CKR_OK);
        if (rv == CKR_OK && key != CK_INVALID_HANDLE)
            funcList->C_DestroyObject(session, key);
    }

    /* Negative: both templates CKA_TOKEN=TRUE rejected. */
    XMEMSET(&kpMech, 0, sizeof(kpMech));
    kpMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    rv = funcList->C_GenerateKeyPair(session, &kpMech,
                                     pubTokenTrue,
                                     sizeof(pubTokenTrue)/sizeof(pubTokenTrue[0]),
                                     privTokenTrue,
                                     sizeof(privTokenTrue)/sizeof(privTokenTrue[0]),
                                     &pubKey, &privKey);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: CKM_RSA_PKCS_KEY_PAIR_GEN not enabled\n");
    } else {
        CHECK_RV(rv, "C_GenerateKeyPair(both=TRUE) on R/O session",
                 CKR_SESSION_READ_ONLY);
        if (rv == CKR_OK) {
            if (pubKey != CK_INVALID_HANDLE)
                funcList->C_DestroyObject(session, pubKey);
            if (privKey != CK_INVALID_HANDLE)
                funcList->C_DestroyObject(session, privKey);
        }

        /* Negative: public CKA_TOKEN=FALSE, private CKA_TOKEN=TRUE must
         * still be rejected — the private template asks for a token
         * object. */
        pubKey = CK_INVALID_HANDLE;
        privKey = CK_INVALID_HANDLE;
        rv = funcList->C_GenerateKeyPair(session, &kpMech,
                                         pubTokenFalse,
                                         sizeof(pubTokenFalse) /
                                             sizeof(pubTokenFalse[0]),
                                         privOnlyToken,
                                         sizeof(privOnlyToken) /
                                             sizeof(privOnlyToken[0]),
                                         &pubKey, &privKey);
        CHECK_RV(rv, "C_GenerateKeyPair(pub=FALSE,priv=TRUE) on R/O",
                 CKR_SESSION_READ_ONLY);
        if (rv == CKR_OK) {
            if (pubKey != CK_INVALID_HANDLE)
                funcList->C_DestroyObject(session, pubKey);
            if (privKey != CK_INVALID_HANDLE)
                funcList->C_DestroyObject(session, privKey);
        }
    }

out:
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
#endif /* !WOLFPKCS11_NSS */
}

/* Create an AES-128 secret key in a session for use by an Init test. The
 * aes_128_key array comes from testdata.h. */
static CK_RV make_aes_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
    static CK_KEY_TYPE aesKeyType = CKK_AES;
    static CK_BBOOL ckTrue = CK_TRUE;
    static CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE tpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_ENCRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_DECRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,    aes_128_key,     16                     },
        /* Tests open public sessions and never C_Login. Explicit
         * CKA_PRIVATE=FALSE keeps the gate from finding 3144 from
         * rejecting these helper keys; finding 2370 (default flip)
         * means CKO_SECRET_KEY would otherwise default to CKA_PRIVATE=TRUE
         * and require login. */
        { CKA_PRIVATE,  &ckFalse,        sizeof(ckFalse)        },
    };
    return funcList->C_CreateObject(session, tpl,
                                    sizeof(tpl) / sizeof(tpl[0]), key);
}

/* Finding 3634: WP11_Session_SetGcmParams crashed (XMEMCPY from NULL) when a
 * caller passed CK_GCM_PARAMS with pIv=NULL and a non-zero ulIvLen. The
 * library must reject this with CKR_MECHANISM_PARAM_INVALID instead of
 * dereferencing. */
static void test_3634_gcm_null_iv(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_GCM_PARAMS params;
    CK_MECHANISM mech;

    printf("\n--- 3634: GCM SetParams rejects NULL pIv with nonzero ulIvLen ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = open_session(CKF_SERIAL_SESSION | CKF_RW_SESSION, &session);
    CHECK_RV(rv, "open R/W session", CKR_OK);
    if (rv != CKR_OK) goto out;

    rv = make_aes_key(session, &key);
    if (rv != CKR_OK) {
        printf("SKIP: AES key creation failed (rv=0x%lx)\n", (unsigned long)rv);
        goto out;
    }

    XMEMSET(&params, 0, sizeof(params));
    params.pIv = NULL;
    params.ulIvLen = 12;        /* nonzero, but no buffer */
    params.pAAD = NULL;
    params.ulAADLen = 0;
    params.ulTagBits = 128;

    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_AES_GCM;
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params);

    rv = funcList->C_EncryptInit(session, &mech, key);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: CKM_AES_GCM not enabled\n");
    } else {
        CHECK_RV(rv, "C_EncryptInit(AES_GCM, pIv=NULL, ulIvLen=12)",
                 CKR_MECHANISM_PARAM_INVALID);
    }

out:
    if (key != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, key);
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

/* Finding 3635: WP11_Session_SetCcmParams had the same NULL pIv crash. */
static void test_3635_ccm_null_iv(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_CCM_PARAMS params;
    CK_MECHANISM mech;

    printf("\n--- 3635: CCM SetParams rejects NULL pIv with nonzero ulIvLen ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = open_session(CKF_SERIAL_SESSION | CKF_RW_SESSION, &session);
    CHECK_RV(rv, "open R/W session", CKR_OK);
    if (rv != CKR_OK) goto out;

    rv = make_aes_key(session, &key);
    if (rv != CKR_OK) {
        printf("SKIP: AES key creation failed (rv=0x%lx)\n", (unsigned long)rv);
        goto out;
    }

    XMEMSET(&params, 0, sizeof(params));
    params.ulDataLen = 16;
    params.pIv = NULL;
    params.ulIvLen = 12;        /* nonzero, but no buffer */
    params.pAAD = NULL;
    params.ulAADLen = 0;
    params.ulMacLen = 16;

    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_AES_CCM;
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params);

    rv = funcList->C_EncryptInit(session, &mech, key);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: CKM_AES_CCM not enabled\n");
    } else {
        CHECK_RV(rv, "C_EncryptInit(AES_CCM, pIv=NULL, ulIvLen=12)",
                 CKR_MECHANISM_PARAM_INVALID);
    }

out:
    if (key != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, key);
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

/* Finding 1340: C_WaitForSlotEvent with CKF_DONT_BLOCK must return
 * CKR_NO_EVENT (this token has no removable slots so there is never an event
 * pending), not CKR_FUNCTION_NOT_SUPPORTED. The non-blocking branch must
 * also still reject malformed inputs: PKCS#11 requires pReserved=NULL, and
 * any unknown flag bit is CKR_ARGUMENTS_BAD. */
static void test_1340_wait_for_slot_event(void)
{
    CK_RV rv;
    CK_SLOT_ID slot;
    int reserved = 1;

    printf("\n--- 1340: C_WaitForSlotEvent(CKF_DONT_BLOCK) returns NO_EVENT ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    /* Happy path. */
    rv = funcList->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL);
    CHECK_RV(rv, "C_WaitForSlotEvent(CKF_DONT_BLOCK)", CKR_NO_EVENT);

    /* Unknown flag bit must be rejected even with CKF_DONT_BLOCK set. */
    rv = funcList->C_WaitForSlotEvent(CKF_DONT_BLOCK | 0x2, &slot, NULL);
    CHECK_RV(rv, "C_WaitForSlotEvent(CKF_DONT_BLOCK | unknown)",
             CKR_ARGUMENTS_BAD);

    /* pReserved must be NULL per spec. */
    rv = funcList->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, &reserved);
    CHECK_RV(rv, "C_WaitForSlotEvent with non-NULL pReserved",
             CKR_ARGUMENTS_BAD);

    /* pSlot is an output parameter and must be non-NULL. */
    rv = funcList->C_WaitForSlotEvent(CKF_DONT_BLOCK, NULL, NULL);
    CHECK_RV(rv, "C_WaitForSlotEvent with NULL pSlot",
             CKR_ARGUMENTS_BAD);

    funcList->C_Finalize(NULL);
}

/* Finding 1339: The four dual-function stubs are unimplemented. They must
 * return CKR_FUNCTION_NOT_SUPPORTED, not CKR_OPERATION_NOT_INITIALIZED. */
static void test_1339_dual_function_stubs(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_BYTE buf[16] = {0};
    CK_ULONG outLen = sizeof(buf);

    printf("\n--- 1339: dual-function stubs return FUNCTION_NOT_SUPPORTED ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = open_ro_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK) goto out;

    rv = funcList->C_DigestEncryptUpdate(session, buf, sizeof(buf), buf,
                                         &outLen);
    CHECK_RV(rv, "C_DigestEncryptUpdate", CKR_FUNCTION_NOT_SUPPORTED);

    rv = funcList->C_DecryptDigestUpdate(session, buf, sizeof(buf), buf,
                                         &outLen);
    CHECK_RV(rv, "C_DecryptDigestUpdate", CKR_FUNCTION_NOT_SUPPORTED);

    rv = funcList->C_SignEncryptUpdate(session, buf, sizeof(buf), buf,
                                       &outLen);
    CHECK_RV(rv, "C_SignEncryptUpdate", CKR_FUNCTION_NOT_SUPPORTED);

    rv = funcList->C_DecryptVerifyUpdate(session, buf, sizeof(buf), buf,
                                         &outLen);
    CHECK_RV(rv, "C_DecryptVerifyUpdate", CKR_FUNCTION_NOT_SUPPORTED);

out:
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

/* Finding 1342: C_DeriveKey must enforce R/W session when the template marks
 * the derived key as a token object. Negative case asserts the rejection;
 * positive case asserts CKA_TOKEN=FALSE still works on R/O so the gate
 * does not over-fire. */
static void test_1342_derive_key_rw_session(void)
{
#ifdef WOLFPKCS11_NSS
    printf("\n--- 1342: C_DeriveKey enforces R/W for token keys ---\n");
    printf("SKIP: NSS builds intentionally treat all sessions as R/W\n");
#else
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_MECHANISM mech;
    CK_ATTRIBUTE tokenTrue[] = {
        { CKA_TOKEN, &ckTrue,  sizeof(ckTrue)  },
    };
    CK_ATTRIBUTE tokenFalse[] = {
        { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
    };

    printf("\n--- 1342: C_DeriveKey enforces R/W for token keys ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = open_ro_session(&session);
    CHECK_RV(rv, "open R/O session", CKR_OK);
    if (rv != CKR_OK) goto out;

    /* Negative: CKA_TOKEN=TRUE must be rejected. The R/W check must run
     * before the base-key lookup, so even an invalid hBaseKey returns
     * CKR_SESSION_READ_ONLY here. */
    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_HKDF_DERIVE;
    rv = funcList->C_DeriveKey(session, &mech, CK_INVALID_HANDLE, tokenTrue,
                               sizeof(tokenTrue) / sizeof(tokenTrue[0]),
                               &derived);
    CHECK_RV(rv, "C_DeriveKey(token=TRUE) on R/O session",
             CKR_SESSION_READ_ONLY);

    /* Positive: CKA_TOKEN=FALSE must NOT trip the R/W gate. The base-key
     * lookup then fails (invalid handle), so we expect any return code
     * except CKR_SESSION_READ_ONLY. */
    rv = funcList->C_DeriveKey(session, &mech, CK_INVALID_HANDLE, tokenFalse,
                               sizeof(tokenFalse) / sizeof(tokenFalse[0]),
                               &derived);
    CHECK_COND_MSG(rv != CKR_SESSION_READ_ONLY,
                   "C_DeriveKey(token=FALSE) on R/O not gated by R/W check");

out:
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
#endif /* !WOLFPKCS11_NSS */
}

/* Finding 3637: SecretObject_GetAttr must return CKR_ATTRIBUTE_SENSITIVE when
 * CKA_VALUE is requested on a CKK_GENERIC_SECRET object that has
 * CKA_SENSITIVE=TRUE, even when CKA_EXTRACTABLE=TRUE. The existing
 * test_attributes_secret coverage always pairs SENSITIVE=FALSE or pairs
 * SENSITIVE=TRUE with EXTRACTABLE=FALSE, so a mutation that drops the
 * SENSITIVE arm of the noPriv disjunction would not be caught. */
static void test_3637_generic_secret_sensitive_attr(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,       &secretKeyClass,  sizeof(secretKeyClass)  },
        { CKA_KEY_TYPE,    &genericKeyType,  sizeof(genericKeyType)  },
        { CKA_SENSITIVE,   &ckTrue,          sizeof(ckTrue)          },
        { CKA_EXTRACTABLE, &ckTrue,          sizeof(ckTrue)          },
        { CKA_VALUE,       aes_128_key,      sizeof(aes_128_key)     },
        { CKA_PRIVATE,     &ckFalse,         sizeof(ckFalse)         },
    };
    CK_BYTE buf[32];
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_VALUE, buf, sizeof(buf) },
    };

    printf("\n--- 3637: generic-secret CKA_VALUE rejects when SENSITIVE ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = open_session(CKF_SERIAL_SESSION | CKF_RW_SESSION, &session);
    CHECK_RV(rv, "open R/W session", CKR_OK);
    if (rv != CKR_OK) goto out;

    rv = funcList->C_CreateObject(session, createTmpl,
                                  sizeof(createTmpl) / sizeof(createTmpl[0]),
                                  &key);
    CHECK_RV(rv, "C_CreateObject(generic_secret, SENSITIVE=TRUE, "
                 "EXTRACTABLE=TRUE)", CKR_OK);
    if (rv != CKR_OK) goto out;

    rv = funcList->C_GetAttributeValue(session, key, getTmpl, 1);
    CHECK_RV(rv, "C_GetAttributeValue(CKA_VALUE) on sensitive generic secret",
             CKR_ATTRIBUTE_SENSITIVE);

out:
    if (key != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, key);
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

/* Finding 2776: The four asymmetric *Object_GetAttr functions
 * (RsaObject_GetAttr, EcObject_GetAttr, DhObject_GetAttr,
 * MldsaObject_GetAttr) historically only set *len = CK_UNAVAILABLE_INFORMATION
 * when noPriv was true and returned 0, leaving C_GetAttributeValue to report
 * CKR_OK. Per PKCS#11, asking for a sensitive attribute must return
 * CKR_ATTRIBUTE_SENSITIVE, matching the symmetric path in
 * SecretObject_GetAttr. The fix also closes the mutation gap noted in the
 * finding: a mutant that drops the SENSITIVE arm of the noPriv disjunction
 * would otherwise survive every existing asymmetric-key test. */
static void test_2776_asymmetric_sensitive_attr(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
#ifndef NO_RSA
    CK_OBJECT_HANDLE rsaKey = CK_INVALID_HANDLE;
#endif
#ifdef HAVE_ECC
    CK_OBJECT_HANDLE ecKey = CK_INVALID_HANDLE;
#endif
#ifndef NO_DH
    CK_OBJECT_HANDLE dhKey = CK_INVALID_HANDLE;
#endif
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_BYTE buf[512];

    (void)privKeyClass;
    (void)ckTrue;
    (void)ckFalse;
    (void)buf;

    printf("\n--- 2776: asymmetric CKA_VALUE/PRIVATE_EXPONENT sensitive ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = open_session(CKF_SERIAL_SESSION | CKF_RW_SESSION, &session);
    CHECK_RV(rv, "open R/W session", CKR_OK);
    if (rv != CKR_OK) goto out;

#ifndef NO_RSA
    {
        CK_KEY_TYPE rsaKeyType = CKK_RSA;
        CK_ATTRIBUTE tpl[] = {
            { CKA_CLASS,            &privKeyClass,     sizeof(privKeyClass)      },
            { CKA_KEY_TYPE,         &rsaKeyType,       sizeof(rsaKeyType)        },
            { CKA_SENSITIVE,        &ckTrue,           sizeof(ckTrue)            },
            { CKA_EXTRACTABLE,      &ckTrue,           sizeof(ckTrue)            },
            { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
            { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
            { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
            { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
            { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
            { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
            { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
            { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
            { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        };
        CK_ATTRIBUTE getTmpl[] = {
            { CKA_PRIVATE_EXPONENT, buf, sizeof(buf) },
        };
        rv = funcList->C_CreateObject(session, tpl,
                                      sizeof(tpl) / sizeof(tpl[0]), &rsaKey);
        CHECK_RV(rv, "C_CreateObject(RSA priv, SENSITIVE=TRUE)", CKR_OK);
        if (rv == CKR_OK) {
            rv = funcList->C_GetAttributeValue(session, rsaKey, getTmpl, 1);
            CHECK_RV(rv, "C_GetAttributeValue(CKA_PRIVATE_EXPONENT) on "
                         "sensitive RSA key", CKR_ATTRIBUTE_SENSITIVE);
        }
    }
#endif

#ifdef HAVE_ECC
    {
        CK_KEY_TYPE eccKeyType = CKK_EC;
        CK_ATTRIBUTE tpl[] = {
            { CKA_CLASS,       &privKeyClass,    sizeof(privKeyClass)    },
            { CKA_KEY_TYPE,    &eccKeyType,      sizeof(eccKeyType)      },
            { CKA_SENSITIVE,   &ckTrue,          sizeof(ckTrue)          },
            { CKA_EXTRACTABLE, &ckTrue,          sizeof(ckTrue)          },
            { CKA_PRIVATE,     &ckFalse,         sizeof(ckFalse)         },
            { CKA_EC_PARAMS,   ecc_p256_params,  sizeof(ecc_p256_params) },
            { CKA_VALUE,       ecc_p256_priv,    sizeof(ecc_p256_priv)   },
        };
        CK_ATTRIBUTE getTmpl[] = {
            { CKA_VALUE, buf, sizeof(buf) },
        };
        rv = funcList->C_CreateObject(session, tpl,
                                      sizeof(tpl) / sizeof(tpl[0]), &ecKey);
        CHECK_RV(rv, "C_CreateObject(EC priv, SENSITIVE=TRUE)", CKR_OK);
        if (rv == CKR_OK) {
            rv = funcList->C_GetAttributeValue(session, ecKey, getTmpl, 1);
            CHECK_RV(rv, "C_GetAttributeValue(CKA_VALUE) on sensitive EC key",
                     CKR_ATTRIBUTE_SENSITIVE);
        }
    }
#endif

#ifndef NO_DH
    {
        CK_KEY_TYPE dhKeyType = CKK_DH;
        CK_ATTRIBUTE tpl[] = {
            { CKA_CLASS,       &privKeyClass,   sizeof(privKeyClass)   },
            { CKA_KEY_TYPE,    &dhKeyType,      sizeof(dhKeyType)      },
            { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
            { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
            { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)        },
            { CKA_PRIME,       dh_ffdhe2048_p,  sizeof(dh_ffdhe2048_p) },
            { CKA_BASE,        dh_ffdhe2048_g,  sizeof(dh_ffdhe2048_g) },
            { CKA_VALUE,       dh_2048_priv,    sizeof(dh_2048_priv)   },
        };
        CK_ATTRIBUTE getTmpl[] = {
            { CKA_VALUE, buf, sizeof(buf) },
        };
        rv = funcList->C_CreateObject(session, tpl,
                                      sizeof(tpl) / sizeof(tpl[0]), &dhKey);
        CHECK_RV(rv, "C_CreateObject(DH priv, SENSITIVE=TRUE)", CKR_OK);
        if (rv == CKR_OK) {
            rv = funcList->C_GetAttributeValue(session, dhKey, getTmpl, 1);
            CHECK_RV(rv, "C_GetAttributeValue(CKA_VALUE) on sensitive DH key",
                     CKR_ATTRIBUTE_SENSITIVE);
        }
    }
#endif

out:
#ifndef NO_RSA
    if (rsaKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, rsaKey);
#endif
#ifdef HAVE_ECC
    if (ecKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, ecKey);
#endif
#ifndef NO_DH
    if (dhKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, dhKey);
#endif
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

/* Finding 3407: C_GetTokenInfo must not advertise CKF_TOKEN_INITIALIZED on a
 * fresh slot. wp11_Slot_Init used to call wp11_Token_Init which unconditionally
 * set token state to INITIALIZED, so an application keying off
 * CKF_TOKEN_INITIALIZED to decide whether provisioning was needed would skip
 * C_InitToken on a token that had never been provisioned. After C_InitToken
 * the flag must appear. */
static void test_3407_fresh_slot_uninitialized(void)
{
    CK_RV rv;
    CK_SLOT_ID slot;
    CK_SLOT_ID* slotList = NULL;
    CK_ULONG slotCount = 0;
    CK_TOKEN_INFO info;
    /* PKCS#11 32-byte space-padded label, no NUL terminator. */
    CK_UTF8CHAR label[32];
    CK_BYTE soPin[] = "password123456";

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "compliance-3407", 15);

    printf("\n--- 3407: fresh slot reports !CKF_TOKEN_INITIALIZED ---\n");

    /* Wipe any persisted token from previous tests in this session so the
     * library starts genuinely fresh. */
    cleanup_store();

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = funcList->C_GetSlotList(CK_TRUE, NULL, &slotCount);
    CHECK_RV(rv, "C_GetSlotList(NULL) count", CKR_OK);
    if (rv != CKR_OK || slotCount == 0) goto out;

    slotList = (CK_SLOT_ID*)XMALLOC(slotCount * sizeof(CK_SLOT_ID), NULL,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (slotList == NULL) goto out;
    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    CHECK_RV(rv, "C_GetSlotList(buf)", CKR_OK);
    if (rv != CKR_OK) goto out;
    slot = slotList[0];

    XMEMSET(&info, 0, sizeof(info));
    rv = funcList->C_GetTokenInfo(slot, &info);
    CHECK_RV(rv, "C_GetTokenInfo on fresh slot", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_COND_MSG(!(info.flags & CKF_TOKEN_INITIALIZED),
                       "CKF_TOKEN_INITIALIZED clear on fresh slot");
    }

    rv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
    CHECK_RV(rv, "C_InitToken", CKR_OK);
    if (rv == CKR_OK) {
        XMEMSET(&info, 0, sizeof(info));
        rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_RV(rv, "C_GetTokenInfo after C_InitToken", CKR_OK);
        if (rv == CKR_OK) {
            CHECK_COND_MSG(info.flags & CKF_TOKEN_INITIALIZED,
                           "CKF_TOKEN_INITIALIZED set after C_InitToken");
        }
    }

out:
    if (slotList != NULL)
        XFREE(slotList, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    funcList->C_Finalize(NULL);
    cleanup_store();
}

/* Finding 1343: C_SetAttributeValue must consult CKA_MODIFIABLE on the
 * target object. If CKA_MODIFIABLE=CK_FALSE, any attempt to change an
 * attribute must return CKR_ACTION_PROHIBITED. PKCS#11 default for
 * CKA_MODIFIABLE is CK_TRUE; the positive arm of the test confirms a key
 * created without the flag is still modifiable. */
static void test_1343_modifiable_enforced(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE lockedKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE plainKey = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesKeyType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE lockedTmpl[] = {
        { CKA_CLASS,      &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,   &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_VALUE,      aes_128_key,     sizeof(aes_128_key)    },
        { CKA_MODIFIABLE, &ckFalse,        sizeof(ckFalse)        },
        { CKA_PRIVATE,    &ckFalse,        sizeof(ckFalse)        },
    };
    CK_ATTRIBUTE plainTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_VALUE,    aes_128_key,     sizeof(aes_128_key)    },
        { CKA_PRIVATE,  &ckFalse,        sizeof(ckFalse)        },
    };
    CK_UTF8CHAR newLabel[] = "1343-relabel";
    CK_ATTRIBUTE setLabelTmpl[] = {
        { CKA_LABEL, newLabel, sizeof(newLabel) - 1 },
    };
    CK_BBOOL getMod = CK_FALSE;
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_MODIFIABLE, &getMod, sizeof(getMod) },
    };

    printf("\n--- 1343: CKA_MODIFIABLE=FALSE blocks SetAttributeValue ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = open_session(CKF_SERIAL_SESSION | CKF_RW_SESSION, &session);
    CHECK_RV(rv, "open R/W session", CKR_OK);
    if (rv != CKR_OK) goto out;

    rv = funcList->C_CreateObject(session, lockedTmpl,
                                  sizeof(lockedTmpl) / sizeof(lockedTmpl[0]),
                                  &lockedKey);
    CHECK_RV(rv, "C_CreateObject(MODIFIABLE=FALSE)", CKR_OK);
    if (rv != CKR_OK) goto out;

    rv = funcList->C_GetAttributeValue(session, lockedKey, getTmpl, 1);
    CHECK_RV(rv, "C_GetAttributeValue(CKA_MODIFIABLE) reads FALSE", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_COND_MSG(getMod == CK_FALSE,
                       "CKA_MODIFIABLE stored as FALSE");
    }

    rv = funcList->C_SetAttributeValue(session, lockedKey, setLabelTmpl, 1);
    CHECK_RV(rv, "C_SetAttributeValue on MODIFIABLE=FALSE object",
             CKR_ACTION_PROHIBITED);

    /* Default CKA_MODIFIABLE must be CK_TRUE so unattributed objects stay
     * mutable per spec. */
    rv = funcList->C_CreateObject(session, plainTmpl,
                                  sizeof(plainTmpl) / sizeof(plainTmpl[0]),
                                  &plainKey);
    CHECK_RV(rv, "C_CreateObject(no CKA_MODIFIABLE)", CKR_OK);
    if (rv == CKR_OK) {
        getMod = CK_FALSE;
        rv = funcList->C_GetAttributeValue(session, plainKey, getTmpl, 1);
        CHECK_RV(rv, "C_GetAttributeValue(CKA_MODIFIABLE) default", CKR_OK);
        if (rv == CKR_OK) {
            CHECK_COND_MSG(getMod == CK_TRUE,
                           "CKA_MODIFIABLE default is CK_TRUE");
        }
        rv = funcList->C_SetAttributeValue(session, plainKey,
                                           setLabelTmpl, 1);
        CHECK_RV(rv, "C_SetAttributeValue on default object", CKR_OK);
    }

    /* CKA_MODIFIABLE=FALSE may be set at creation time but must not be
     * settable after the fact via C_SetAttributeValue - the gate is already
     * the CKA_MODIFIABLE check, regardless of what the new value would
     * be. */
    {
        CK_ATTRIBUTE relockTmpl[] = {
            { CKA_MODIFIABLE, &ckFalse, sizeof(ckFalse) },
        };
        rv = funcList->C_SetAttributeValue(session, lockedKey, relockTmpl, 1);
        CHECK_RV(rv, "C_SetAttributeValue rejects re-locking a locked object",
                 CKR_ACTION_PROHIBITED);
        (void)ckTrue;
    }

out:
    if (lockedKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, lockedKey);
    if (plainKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, plainKey);
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

/* Finding 3144: PKCS#11 v3.0 sec 5.1 Table 16 requires the four object-
 * creation entry points (C_CreateObject, C_GenerateKey, C_GenerateKeyPair,
 * C_UnwrapKey) to return CKR_USER_NOT_LOGGED_IN when the template requests
 * CKA_PRIVATE=TRUE on a session that is not logged in as the user. The token
 * is initialised with a non-empty user PIN so the empty-PIN bypass does not
 * mask the check. */
static void test_3144_private_create_requires_login(void)
{
    CK_RV rv;
    CK_SLOT_ID slot;
    CK_SLOT_ID* slotList = NULL;
    CK_ULONG slotCount = 0;
    CK_SESSION_HANDLE soSession = 0;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privKey = CK_INVALID_HANDLE;
    CK_UTF8CHAR label[32];
    CK_BYTE soPin[] = "password123456";
    CK_BYTE userPin[] = "someUserPin";
    CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_ATTRIBUTE createPrivTmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_PRIVATE,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,       aes_128_key,     sizeof(aes_128_key)    },
    };
    CK_ULONG aesKeyLen = 16;
    CK_KEY_TYPE aesKeyType = CKK_AES;
    CK_ATTRIBUTE genPrivTmpl[] = {
        { CKA_CLASS,     &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,  &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_PRIVATE,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN, &aesKeyLen,      sizeof(aesKeyLen)      },
    };
    /* aes_keygen_attrs_test style: implicit class (C_GenerateKey always
     * creates a secret key), no explicit CKA_CLASS or CKA_PRIVATE. The
     * implicit class + spec-default CKA_PRIVATE=CK_TRUE must still trigger
     * the login gate. */
    CK_ATTRIBUTE genImplicitTmpl[] = {
        { CKA_KEY_TYPE,  &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_VALUE_LEN, &aesKeyLen,      sizeof(aesKeyLen)      },
    };
    CK_MECHANISM aesMech;
    CK_MECHANISM rsaKpMech;
    CK_ATTRIBUTE rsaPubTmpl[] = {
        { CKA_PRIVATE, &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE rsaPrivTmpl[] = {
        { CKA_PRIVATE, &ckTrue, sizeof(ckTrue) },
    };

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "compliance-3144", 15);

    printf("\n--- 3144: private object creation needs login ---\n");

    cleanup_store();
    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = funcList->C_GetSlotList(CK_TRUE, NULL, &slotCount);
    if (rv != CKR_OK || slotCount == 0) goto out;
    slotList = (CK_SLOT_ID*)XMALLOC(slotCount * sizeof(CK_SLOT_ID), NULL,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (slotList == NULL) goto out;
    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv != CKR_OK) goto out;
    slot = slotList[0];

    /* Provision a real (non-empty) user PIN so the empty-PIN bypass does
     * not cover for the missing login check. */
    rv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
    CHECK_RV(rv, "C_InitToken", CKR_OK);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &soSession);
    CHECK_RV(rv, "C_OpenSession(SO)", CKR_OK);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_Login(soSession, CKU_SO, soPin, sizeof(soPin) - 1);
    CHECK_RV(rv, "C_Login(SO)", CKR_OK);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_InitPIN(soSession, userPin, sizeof(userPin) - 1);
    CHECK_RV(rv, "C_InitPIN", CKR_OK);
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    soSession = 0;

    /* Open a fresh public (not logged-in) session and try each of the four
     * entry points with CKA_PRIVATE=TRUE. */
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    CHECK_RV(rv, "C_OpenSession(public)", CKR_OK);
    if (rv != CKR_OK) goto out;

    rv = funcList->C_CreateObject(session, createPrivTmpl,
                                  sizeof(createPrivTmpl) /
                                      sizeof(createPrivTmpl[0]),
                                  &obj);
    CHECK_RV(rv, "C_CreateObject(CKA_PRIVATE=TRUE) public session",
             CKR_USER_NOT_LOGGED_IN);
    if (rv == CKR_OK && obj != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, obj);

    XMEMSET(&aesMech, 0, sizeof(aesMech));
    aesMech.mechanism = CKM_AES_KEY_GEN;
    obj = CK_INVALID_HANDLE;
    rv = funcList->C_GenerateKey(session, &aesMech, genPrivTmpl,
                                 sizeof(genPrivTmpl) / sizeof(genPrivTmpl[0]),
                                 &obj);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: CKM_AES_KEY_GEN not enabled\n");
    } else {
        CHECK_RV(rv, "C_GenerateKey(CKA_PRIVATE=TRUE) public session",
                 CKR_USER_NOT_LOGGED_IN);
        if (rv == CKR_OK && obj != CK_INVALID_HANDLE)
            funcList->C_DestroyObject(session, obj);

        /* Implicit class via API: template lacks CKA_CLASS *and*
         * CKA_PRIVATE. C_GenerateKey always creates a secret key, so the
         * spec-default CKA_PRIVATE=CK_TRUE must still gate login. */
        obj = CK_INVALID_HANDLE;
        rv = funcList->C_GenerateKey(session, &aesMech, genImplicitTmpl,
                                     sizeof(genImplicitTmpl) /
                                         sizeof(genImplicitTmpl[0]),
                                     &obj);
        CHECK_RV(rv, "C_GenerateKey(no CKA_CLASS/CKA_PRIVATE) public session",
                 CKR_USER_NOT_LOGGED_IN);
        if (rv == CKR_OK && obj != CK_INVALID_HANDLE)
            funcList->C_DestroyObject(session, obj);
    }

    XMEMSET(&rsaKpMech, 0, sizeof(rsaKpMech));
    rsaKpMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    rv = funcList->C_GenerateKeyPair(session, &rsaKpMech,
                                     rsaPubTmpl,
                                     sizeof(rsaPubTmpl)/sizeof(rsaPubTmpl[0]),
                                     rsaPrivTmpl,
                                     sizeof(rsaPrivTmpl)/sizeof(rsaPrivTmpl[0]),
                                     &pubKey, &privKey);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: CKM_RSA_PKCS_KEY_PAIR_GEN not enabled\n");
    } else {
        CHECK_RV(rv,
                 "C_GenerateKeyPair(private template CKA_PRIVATE=TRUE) "
                 "public session", CKR_USER_NOT_LOGGED_IN);
        if (rv == CKR_OK) {
            if (pubKey != CK_INVALID_HANDLE)
                funcList->C_DestroyObject(session, pubKey);
            if (privKey != CK_INVALID_HANDLE)
                funcList->C_DestroyObject(session, privKey);
        }
    }

    /* Sanity sibling: after C_Login as user, the same C_CreateObject must
     * succeed. Confirms the gate is the login state, not something else. */
    rv = funcList->C_Login(session, CKU_USER, userPin, sizeof(userPin) - 1);
    CHECK_RV(rv, "C_Login(user)", CKR_OK);
    if (rv == CKR_OK) {
        obj = CK_INVALID_HANDLE;
        rv = funcList->C_CreateObject(session, createPrivTmpl,
                                      sizeof(createPrivTmpl) /
                                          sizeof(createPrivTmpl[0]),
                                      &obj);
        CHECK_RV(rv, "C_CreateObject(CKA_PRIVATE=TRUE) after login", CKR_OK);
        if (rv == CKR_OK && obj != CK_INVALID_HANDLE)
            funcList->C_DestroyObject(session, obj);
        funcList->C_Logout(session);
    }

out:
    if (slotList != NULL)
        XFREE(slotList, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (session != 0)
        funcList->C_CloseSession(session);
    if (soSession != 0)
        funcList->C_CloseSession(soSession);
    funcList->C_Finalize(NULL);
    cleanup_store();
}

/* Finding 2370: When a template omits CKA_PRIVATE, PKCS#11 v2.40 sec 4.4.1
 * requires the default to be CK_TRUE for private and secret keys, CK_FALSE
 * for public keys. wolfPKCS11 used to default unconditionally to CK_FALSE
 * because SetAttributeDefaults never set CKA_PRIVATE. The fix gates the
 * spec-correct default behind WOLFPKCS11_LEGACY_PRIVATE_FALSE_DEFAULT;
 * unless that macro is defined, the test asserts CK_TRUE. */
static void test_2370_private_default(void)
{
    CK_RV rv;
    CK_SLOT_ID slot;
    CK_SLOT_ID* slotList = NULL;
    CK_ULONG slotCount = 0;
    CK_SESSION_HANDLE soSession = 0;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE secretKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privKey = CK_INVALID_HANDLE;
    CK_BYTE soPin[] = "password123456";
    CK_BYTE userPin[] = "someUserPin";
    CK_UTF8CHAR label[32];
    CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE aesKeyType = CKK_AES;
    CK_ULONG aesKeyLen = 16;
    CK_MECHANISM aesMech;
    CK_ATTRIBUTE secretTmpl[] = {
        { CKA_CLASS,     &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,  &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_VALUE_LEN, &aesKeyLen,      sizeof(aesKeyLen)      },
    };
    CK_BBOOL gotPrivate = CK_FALSE;
    CK_ATTRIBUTE getPrivTmpl[] = {
        { CKA_PRIVATE, &gotPrivate, sizeof(gotPrivate) },
    };
    /* CKO_PUBLIC_KEY default is CKA_PRIVATE=CK_FALSE per spec. */
    CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,       &pubKeyClass,    sizeof(pubKeyClass)    },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,       aes_128_key,     sizeof(aes_128_key)    },
    };

    (void)pubKey;
    (void)privKey;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "compliance-2370", 15);

    printf("\n--- 2370: CKA_PRIVATE default is CK_TRUE for private/secret "
           "keys ---\n");

    cleanup_store();
    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = funcList->C_GetSlotList(CK_TRUE, NULL, &slotCount);
    if (rv != CKR_OK || slotCount == 0) goto out;
    slotList = (CK_SLOT_ID*)XMALLOC(slotCount * sizeof(CK_SLOT_ID), NULL,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (slotList == NULL) goto out;
    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv != CKR_OK) goto out;
    slot = slotList[0];

    /* Provision token + user PIN so we can log in as user before creating
     * a key that would (now) default to CKA_PRIVATE=TRUE. */
    rv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
    CHECK_RV(rv, "C_InitToken", CKR_OK);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &soSession);
    CHECK_RV(rv, "C_OpenSession(SO)", CKR_OK);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_Login(soSession, CKU_SO, soPin, sizeof(soPin) - 1);
    CHECK_RV(rv, "C_Login(SO)", CKR_OK);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_InitPIN(soSession, userPin, sizeof(userPin) - 1);
    CHECK_RV(rv, "C_InitPIN", CKR_OK);
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    soSession = 0;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    CHECK_RV(rv, "C_OpenSession(user)", CKR_OK);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_Login(session, CKU_USER, userPin, sizeof(userPin) - 1);
    CHECK_RV(rv, "C_Login(USER)", CKR_OK);
    if (rv != CKR_OK) goto out;

    /* Secret key without explicit CKA_PRIVATE in template. */
    XMEMSET(&aesMech, 0, sizeof(aesMech));
    aesMech.mechanism = CKM_AES_KEY_GEN;
    rv = funcList->C_GenerateKey(session, &aesMech, secretTmpl,
                                 sizeof(secretTmpl) / sizeof(secretTmpl[0]),
                                 &secretKey);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: CKM_AES_KEY_GEN not enabled\n");
    } else {
        CHECK_RV(rv, "C_GenerateKey(no CKA_PRIVATE) as user", CKR_OK);
        if (rv == CKR_OK) {
            gotPrivate = CK_FALSE;
            rv = funcList->C_GetAttributeValue(session, secretKey,
                                               getPrivTmpl, 1);
            CHECK_RV(rv, "C_GetAttributeValue(CKA_PRIVATE) on secret key",
                     CKR_OK);
            if (rv == CKR_OK) {
                CHECK_COND_MSG(gotPrivate == CK_TRUE,
                               "secret-key default CKA_PRIVATE is CK_TRUE");
            }
        }
    }

    /* Public-key default must remain CK_FALSE so the public arm of a key
     * pair stays accessible from public sessions. Use C_CreateObject so we
     * don't need a key-pair-generation mechanism enabled. */
    rv = funcList->C_CreateObject(session, pubTmpl,
                                  sizeof(pubTmpl) / sizeof(pubTmpl[0]),
                                  &pubKey);
    CHECK_RV(rv, "C_CreateObject(public, no CKA_PRIVATE)", CKR_OK);
    if (rv == CKR_OK) {
        gotPrivate = CK_TRUE;
        rv = funcList->C_GetAttributeValue(session, pubKey, getPrivTmpl, 1);
        CHECK_RV(rv, "C_GetAttributeValue(CKA_PRIVATE) on public key",
                 CKR_OK);
        if (rv == CKR_OK) {
            CHECK_COND_MSG(gotPrivate == CK_FALSE,
                           "public-key default CKA_PRIVATE is CK_FALSE");
        }
    }

out:
    if (slotList != NULL)
        XFREE(slotList, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (secretKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, secretKey);
    if (pubKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pubKey);
    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    if (soSession != 0)
        funcList->C_CloseSession(soSession);
    funcList->C_Finalize(NULL);
    cleanup_store();
}

/* Finding 2774: PKCS#11 v2.40 sec 4.4.1: when a template omits CKA_WRAP and
 * CKA_UNWRAP, both default to CK_FALSE. wolfPKCS11 used to default both to
 * CK_TRUE for AES secret keys and RSA key pairs, silently turning every
 * key into a wrapping key. The fix is gated behind
 * WOLFPKCS11_LEGACY_WRAP_TRUE_DEFAULT; unless that macro is defined, the
 * test asserts CK_FALSE. */
static void test_2774_wrap_default(void)
{
    CK_RV rv;
    CK_SLOT_ID slot;
    CK_SLOT_ID* slotList = NULL;
    CK_ULONG slotCount = 0;
    CK_SESSION_HANDLE soSession = 0;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
#ifndef NO_RSA
    CK_OBJECT_HANDLE rsaPub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsaPriv = CK_INVALID_HANDLE;
#endif
    CK_BYTE soPin[] = "password123456";
    CK_BYTE userPin[] = "someUserPin";
    CK_UTF8CHAR label[32];
    CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesKeyType = CKK_AES;
    CK_ULONG aesKeyLen = 16;
    CK_MECHANISM aesMech;
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,     &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,  &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_VALUE_LEN, &aesKeyLen,      sizeof(aesKeyLen)      },
    };
#ifndef NO_RSA
    CK_MECHANISM rsaKpMech;
    CK_ULONG rsaBits = 2048;
    CK_ATTRIBUTE rsaPubTmpl[] = {
        { CKA_MODULUS_BITS,    &rsaBits,         sizeof(rsaBits)          },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };
    CK_ATTRIBUTE rsaPrivTmpl[] = {
        { CKA_TOKEN, NULL, 0 },
    };
#endif
    CK_BBOOL gotBool = CK_TRUE;
    CK_ATTRIBUTE getWrapTmpl[] = {
        { CKA_WRAP, &gotBool, sizeof(gotBool) },
    };
    CK_ATTRIBUTE getUnwrapTmpl[] = {
        { CKA_UNWRAP, &gotBool, sizeof(gotBool) },
    };

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "compliance-2774", 15);

    printf("\n--- 2774: CKA_WRAP/UNWRAP default is CK_FALSE ---\n");

    cleanup_store();
    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = funcList->C_GetSlotList(CK_TRUE, NULL, &slotCount);
    if (rv != CKR_OK || slotCount == 0) goto out;
    slotList = (CK_SLOT_ID*)XMALLOC(slotCount * sizeof(CK_SLOT_ID), NULL,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (slotList == NULL) goto out;
    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv != CKR_OK) goto out;
    slot = slotList[0];

    /* Init + login (CKA_PRIVATE default is now TRUE for these keys per
     * finding 2370). */
    rv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
    CHECK_RV(rv, "C_InitToken", CKR_OK);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &soSession);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_Login(soSession, CKU_SO, soPin, sizeof(soPin) - 1);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_InitPIN(soSession, userPin, sizeof(userPin) - 1);
    CHECK_RV(rv, "C_InitPIN", CKR_OK);
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    soSession = 0;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv != CKR_OK) goto out;
    rv = funcList->C_Login(session, CKU_USER, userPin, sizeof(userPin) - 1);
    CHECK_RV(rv, "C_Login(USER)", CKR_OK);
    if (rv != CKR_OK) goto out;

    /* AES secret key: both CKA_WRAP and CKA_UNWRAP must default to FALSE. */
    XMEMSET(&aesMech, 0, sizeof(aesMech));
    aesMech.mechanism = CKM_AES_KEY_GEN;
    rv = funcList->C_GenerateKey(session, &aesMech, aesTmpl,
                                 sizeof(aesTmpl) / sizeof(aesTmpl[0]),
                                 &aesKey);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: CKM_AES_KEY_GEN not enabled\n");
    } else {
        CHECK_RV(rv, "C_GenerateKey(AES, no CKA_WRAP)", CKR_OK);
        if (rv == CKR_OK) {
            gotBool = CK_TRUE;
            rv = funcList->C_GetAttributeValue(session, aesKey, getWrapTmpl,
                                               1);
            CHECK_RV(rv, "C_GetAttributeValue(CKA_WRAP) on AES", CKR_OK);
            if (rv == CKR_OK) {
                CHECK_COND_MSG(gotBool == CK_FALSE,
                               "AES default CKA_WRAP is CK_FALSE");
            }
            gotBool = CK_TRUE;
            rv = funcList->C_GetAttributeValue(session, aesKey,
                                               getUnwrapTmpl, 1);
            CHECK_RV(rv, "C_GetAttributeValue(CKA_UNWRAP) on AES", CKR_OK);
            if (rv == CKR_OK) {
                CHECK_COND_MSG(gotBool == CK_FALSE,
                               "AES default CKA_UNWRAP is CK_FALSE");
            }
        }
    }

    /* RSA key pair: public CKA_WRAP and private CKA_UNWRAP must default to
     * FALSE. */
#ifndef NO_RSA
    XMEMSET(&rsaKpMech, 0, sizeof(rsaKpMech));
    rsaKpMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    rv = funcList->C_GenerateKeyPair(session, &rsaKpMech,
                                     rsaPubTmpl,
                                     sizeof(rsaPubTmpl)/sizeof(rsaPubTmpl[0]),
                                     rsaPrivTmpl, 0,
                                     &rsaPub, &rsaPriv);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: CKM_RSA_PKCS_KEY_PAIR_GEN not enabled\n");
    } else {
        CHECK_RV(rv, "C_GenerateKeyPair(RSA, no CKA_WRAP)", CKR_OK);
        if (rv == CKR_OK) {
            gotBool = CK_TRUE;
            rv = funcList->C_GetAttributeValue(session, rsaPub, getWrapTmpl,
                                               1);
            CHECK_RV(rv, "C_GetAttributeValue(CKA_WRAP) on RSA pub", CKR_OK);
            if (rv == CKR_OK) {
                CHECK_COND_MSG(gotBool == CK_FALSE,
                               "RSA pub default CKA_WRAP is CK_FALSE");
            }
            gotBool = CK_TRUE;
            rv = funcList->C_GetAttributeValue(session, rsaPriv,
                                               getUnwrapTmpl, 1);
            CHECK_RV(rv, "C_GetAttributeValue(CKA_UNWRAP) on RSA priv",
                     CKR_OK);
            if (rv == CKR_OK) {
                CHECK_COND_MSG(gotBool == CK_FALSE,
                               "RSA priv default CKA_UNWRAP is CK_FALSE");
            }
        }
    }
#endif /* !NO_RSA */

out:
    if (slotList != NULL)
        XFREE(slotList, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (aesKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, aesKey);
#ifndef NO_RSA
    if (rsaPub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, rsaPub);
    if (rsaPriv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, rsaPriv);
#endif
    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    if (soSession != 0)
        funcList->C_CloseSession(soSession);
    funcList->C_Finalize(NULL);
    cleanup_store();
}

/* Finding 1336: C_Finalize must reject a non-NULL pReserved with
 * CKR_ARGUMENTS_BAD. */
static void test_1336_finalize_reserved_arg(void)
{
    CK_RV rv;
    int reserved = 1;

    printf("\n--- 1336: C_Finalize validates pReserved ---\n");

    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK) return;

    rv = funcList->C_Finalize(&reserved);
    CHECK_RV(rv, "C_Finalize with non-NULL pReserved", CKR_ARGUMENTS_BAD);

    /* Library must still be initialized after the rejection. */
    rv = funcList->C_Finalize(NULL);
    CHECK_RV(rv, "C_Finalize cleanup", CKR_OK);
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", COMPLIANCE_TEST_DIR, 1);
#endif

    cleanup_store();

    printf("=== wolfPKCS11 PKCS#11 compliance regression tests ===\n");

    if (pkcs11_load() != CKR_OK) {
        fprintf(stderr, "Failed to load PKCS#11 library\n");
        return 1;
    }

    test_3399_get_slot_list_buffer_too_small();
    test_1337_finalize_before_init();
    test_1336_finalize_reserved_arg();
    test_3140_initialize_partial_mutex_callbacks();
    test_1338_generate_key_rw_session();
    test_1342_derive_key_rw_session();
    test_1339_dual_function_stubs();
    test_1340_wait_for_slot_event();
    test_3634_gcm_null_iv();
    test_3635_ccm_null_iv();
    test_3637_generic_secret_sensitive_attr();
    test_2776_asymmetric_sensitive_attr();
    test_3407_fresh_slot_uninitialized();
    test_1343_modifiable_enforced();
    test_3144_private_create_requires_login();
    test_2370_private_default();
    test_2774_wrap_default();

    pkcs11_unload();

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");

    return (test_failed == 0) ? 0 : 1;
}
