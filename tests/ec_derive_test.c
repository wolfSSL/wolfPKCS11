/* ec_derive_test.c
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
 * Tests for C_DeriveKey with CKM_ECDH1_DERIVE: mechanism parameter
 * validation and the attributes of the derived key object.
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

#if defined(HAVE_ECC) && !defined(WOLFPKCS11_NO_STORE) && !defined(_WIN32)
    #define EC_DERIVE_PERSIST_TEST
    #include <unistd.h>
    #include <sys/wait.h>
#endif

#include "testdata.h"

#if defined(HAVE_ECC) && !defined(SINGLE_THREADED) && \
    !defined(WOLFPKCS11_SINGLE_THREADED)
    #define EC_DERIVE_THREAD_TEST
    #include <pthread.h>
#endif

#define TEST_DIR "./store/ec_derive_test"

static int test_passed = 0;
static int test_failed = 0;
static int test_skipped = 0;

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

#define CHECK_RV(rv, exp, op) do {                                        \
    if ((rv) != (exp)) {                                                  \
        fprintf(stderr, "FAIL: %s: got 0x%lx, expected 0x%lx\n", op,      \
                (unsigned long)(rv), (unsigned long)(exp));               \
        test_failed++;                                                    \
        result = -1;                                                      \
        goto cleanup;                                                     \
    }                                                                     \
    else {                                                                \
        printf("PASS: %s\n", op);                                         \
        test_passed++;                                                    \
    }                                                                     \
} while (0)

#define CHECK_CKR(rv, op) CHECK_RV(rv, CKR_OK, op)

#ifdef HAVE_ECC
static CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE eccKeyType = CKK_EC;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_ULONG secretLen = 32;

/* Session P-256 private key usable for ECDH. */
static CK_RV create_ec_base(CK_SESSION_HANDLE session, CK_BBOOL sensitive,
                            CK_BBOOL extractable, CK_OBJECT_HANDLE* obj)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &privKeyClass,   sizeof(privKeyClass)    },
        { CKA_KEY_TYPE,    &eccKeyType,     sizeof(eccKeyType)      },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_SENSITIVE,   &sensitive,      sizeof(sensitive)       },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)     },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS,   ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,       ecc_p256_priv,   sizeof(ecc_p256_priv)   },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, cnt, obj);
}

static CK_RV ecdh_derive_tmpl(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE base,
                              CK_ECDH1_DERIVE_PARAMS* params,
                              CK_ATTRIBUTE* tmpl, CK_ULONG cnt,
                              CK_OBJECT_HANDLE* derived)
{
    CK_MECHANISM mech;

    mech.mechanism = CKM_ECDH1_DERIVE;
    mech.pParameter = params;
    mech.ulParameterLen = sizeof(*params);

    return funcList->C_DeriveKey(session, &mech, base, tmpl, cnt, derived);
}

/* ECDH derive of a public, extractable generic secret. */
static CK_RV ecdh_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                         CK_ECDH1_DERIVE_PARAMS* params,
                         CK_OBJECT_HANDLE* derived)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &secretLen,      sizeof(secretLen)      },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    return ecdh_derive_tmpl(session, base, params, tmpl, cnt, derived);
}

static void ecdh_params_init(CK_ECDH1_DERIVE_PARAMS* params, byte* point,
                             CK_ULONG pointLen)
{
    XMEMSET(params, 0, sizeof(*params));
    params->kdf = CKD_NULL;
    params->pSharedData = NULL;
    params->ulSharedDataLen = 0;
    params->pPublicData = point;
    params->ulPublicDataLen = pointLen;
}

/* With CKD_NULL there is no KDF, so shared data must be absent. */
static int test_null_kdf_shared_data(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS params;
    byte sharedData[4] = { 0x01, 0x02, 0x03, 0x04 };
    int result = 0;

    ret = create_ec_base(session, CK_FALSE, CK_TRUE, &base);
    CHECK_CKR(ret, "create EC base key");

    ecdh_params_init(&params, ecc_p256_point, sizeof(ecc_p256_point));
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_CKR(ret, "CKD_NULL derive without shared data");
    funcList->C_DestroyObject(session, derived);
    derived = CK_INVALID_HANDLE;

    params.pSharedData = sharedData;
    params.ulSharedDataLen = sizeof(sharedData);
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "CKD_NULL derive rejects shared data");

    params.pSharedData = NULL;
    params.ulSharedDataLen = sizeof(sharedData);
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "CKD_NULL derive rejects shared data length");

    params.pSharedData = sharedData;
    params.ulSharedDataLen = 0;
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "CKD_NULL derive rejects shared data pointer");

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    return result;
}

/* A public data length beyond any encodable EC point is a parameter error. */
static int test_public_data_length_bound(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS params;
    byte bigPoint[512];
    CK_ULONG wideLen;
    int result = 0;

    ret = create_ec_base(session, CK_FALSE, CK_TRUE, &base);
    CHECK_CKR(ret, "create EC base key");

    if (sizeof(CK_ULONG) > sizeof(word32)) {
        /* Upper bits set, low 32 bits equal to the real point length. */
        wideLen = ((CK_ULONG)2 << 16) << 16;
        wideLen += sizeof(ecc_p256_point);
        ecdh_params_init(&params, ecc_p256_point, wideLen);
        ret = ecdh_derive(session, base, &params, &derived);
        CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
                 "public data length above 32 bits rejected");
    }

    XMEMSET(bigPoint, 0, sizeof(bigPoint));
    XMEMCPY(bigPoint, ecc_p256_point, sizeof(ecc_p256_point));
    ecdh_params_init(&params, bigPoint, sizeof(bigPoint));
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "oversized public data length rejected");

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    return result;
}

/* An EC point wrapped with an unsupported DER length form is not accepted. */
static int test_unsupported_der_length_form(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS params;
    CK_MECHANISM genMech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    byte p521Params[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
    byte derPoint[2 * 66 + 4];
    byte badPoint[2 * 66 + 3];
    CK_ATTRIBUTE pointAttr = { CKA_EC_POINT, derPoint, sizeof(derPoint) };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, p521Params, sizeof(p521Params) },
        { CKA_PRIVATE,   &ckFalse,   sizeof(ckFalse)    },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_PRIVATE,   &ckFalse,   sizeof(ckFalse)    },
        { CKA_SENSITIVE, &ckFalse,   sizeof(ckFalse)    },
        { CKA_DERIVE,    &ckTrue,    sizeof(ckTrue)     },
    };
    int result = 0;

    ret = funcList->C_GenerateKeyPair(session, &genMech, pubTmpl,
            sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
    if (ret != CKR_OK) {
        printf("SKIP: P-521 key generation unavailable (0x%lx)\n",
               (unsigned long)ret);
        test_skipped = 1;
        goto cleanup;
    }

    ret = funcList->C_GetAttributeValue(session, pub, &pointAttr, 1);
    CHECK_CKR(ret, "read P-521 EC point");
    if (pointAttr.ulValueLen != sizeof(derPoint) || derPoint[0] != 0x04 ||
            derPoint[1] != 0x81 || derPoint[2] != sizeof(badPoint) - 2) {
        ret = CKR_GENERAL_ERROR;
    }
    CHECK_CKR(ret, "P-521 EC point is DER wrapped");

    ecdh_params_init(&params, derPoint, sizeof(derPoint));
    ret = ecdh_derive(session, priv, &params, &derived);
    CHECK_CKR(ret, "derive with DER wrapped point");
    funcList->C_DestroyObject(session, derived);
    derived = CK_INVALID_HANDLE;

    /* Same point with a long-form length byte that has no length octets. */
    badPoint[0] = 0x04;
    badPoint[1] = (byte)(sizeof(badPoint) - 2);
    XMEMCPY(badPoint + 2, derPoint + 3, sizeof(badPoint) - 2);
    ecdh_params_init(&params, badPoint, sizeof(badPoint));
    ret = ecdh_derive(session, priv, &params, &derived);
    if (ret == CKR_OK) {
        fprintf(stderr, "FAIL: malformed DER length form accepted\n");
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: malformed DER length form rejected\n");
    test_passed++;

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
    return result;
}

/* The DER length of a wrapped point must fit in the supplied public data. */
static int test_der_length_within_public_data(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS params;
    byte wrapped[3 + sizeof(ecc_p256_point)];
    int result = 0;

    ret = create_ec_base(session, CK_FALSE, CK_TRUE, &base);
    CHECK_CKR(ret, "create EC base key");

    wrapped[0] = 0x04;
    wrapped[1] = 0x81;
    wrapped[2] = (byte)sizeof(ecc_p256_point);
    XMEMCPY(wrapped + 3, ecc_p256_point, sizeof(ecc_p256_point));

    ecdh_params_init(&params, wrapped, sizeof(wrapped));
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_CKR(ret, "derive with complete DER wrapped point");
    funcList->C_DestroyObject(session, derived);
    derived = CK_INVALID_HANDLE;

    /* Declared length runs past the end of the supplied public data. */
    ecdh_params_init(&params, wrapped, sizeof(wrapped) - 2);
    ret = ecdh_derive(session, base, &params, &derived);
    if (ret == CKR_OK) {
        fprintf(stderr, "FAIL: truncated DER wrapped point accepted\n");
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: truncated DER wrapped point rejected\n");
    test_passed++;

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    return result;
}

/* Repeated derives with one base key leave it usable and give one secret. */
static int test_repeated_derive_same_key(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS params;
    byte secret[sizeof(ecc_secret_256)];
    CK_ATTRIBUTE valAttr = { CKA_VALUE, secret, sizeof(secret) };
    int i;
    int result = 0;

    ret = create_ec_base(session, CK_FALSE, CK_TRUE, &base);
    CHECK_CKR(ret, "create EC base key");

    ecdh_params_init(&params, ecc_p256_point, sizeof(ecc_p256_point));
    for (i = 0; i < 3; i++) {
        ret = ecdh_derive(session, base, &params, &derived);
        CHECK_CKR(ret, "repeated derive with one base key");
        XMEMSET(secret, 0, sizeof(secret));
        valAttr.ulValueLen = sizeof(secret);
        ret = funcList->C_GetAttributeValue(session, derived, &valAttr, 1);
        CHECK_CKR(ret, "read derived secret");
        if (valAttr.ulValueLen != sizeof(ecc_secret_256) ||
                XMEMCMP(secret, ecc_secret_256, sizeof(secret)) != 0) {
            ret = CKR_GENERAL_ERROR;
        }
        CHECK_CKR(ret, "derived secret matches expected value");
        ret = funcList->C_DestroyObject(session, derived);
        derived = CK_INVALID_HANDLE;
        CHECK_CKR(ret, "destroy derived secret");
    }

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    return result;
}

#ifdef EC_DERIVE_THREAD_TEST
#define DERIVE_THREADS     2
#define DERIVES_PER_THREAD 200

typedef struct DeriveCtx {
    CK_OBJECT_HANDLE base;
    int failures;
} DeriveCtx;

static pthread_mutex_t deriveGateLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t deriveGateCond = PTHREAD_COND_INITIALIZER;
static int deriveGateReady = 0;
static int deriveGateOpen = 0;

/* Hold each worker until every worker has arrived so their derives overlap. */
static void derive_gate_wait(void)
{
    if (pthread_mutex_lock(&deriveGateLock) == 0) {
        deriveGateReady++;
        (void)pthread_cond_broadcast(&deriveGateCond);
        while (!deriveGateOpen) {
            if (pthread_cond_wait(&deriveGateCond, &deriveGateLock) != 0)
                break;
        }
        (void)pthread_mutex_unlock(&deriveGateLock);
    }
}

static int derive_gate_open(int workers)
{
    int ret;

    ret = pthread_mutex_lock(&deriveGateLock);
    if (ret == 0) {
        while (ret == 0 && deriveGateReady < workers)
            ret = pthread_cond_wait(&deriveGateCond, &deriveGateLock);
        deriveGateOpen = 1;
        if (pthread_cond_broadcast(&deriveGateCond) != 0)
            ret = -1;
        if (pthread_mutex_unlock(&deriveGateLock) != 0)
            ret = -1;
    }
    return ret;
}

static void* derive_worker(void* arg)
{
    DeriveCtx* ctx = (DeriveCtx*)arg;
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived;
    CK_ECDH1_DERIVE_PARAMS params;
    byte secret[sizeof(ecc_secret_256)];
    CK_ATTRIBUTE valAttr = { CKA_VALUE, secret, sizeof(secret) };
    int i;

    derive_gate_wait();
    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  NULL, NULL, &session);
    if (ret != CKR_OK) {
        ctx->failures = DERIVES_PER_THREAD;
        return NULL;
    }

    ecdh_params_init(&params, ecc_p256_point, sizeof(ecc_p256_point));
    for (i = 0; i < DERIVES_PER_THREAD; i++) {
        derived = CK_INVALID_HANDLE;
        ret = ecdh_derive(session, ctx->base, &params, &derived);
        if (ret == CKR_OK) {
            valAttr.ulValueLen = sizeof(secret);
            ret = funcList->C_GetAttributeValue(session, derived, &valAttr, 1);
        }
        if (ret == CKR_OK && (valAttr.ulValueLen != sizeof(ecc_secret_256) ||
                XMEMCMP(secret, ecc_secret_256, sizeof(secret)) != 0)) {
            ret = CKR_GENERAL_ERROR;
        }
        if (derived != CK_INVALID_HANDLE && ret == CKR_OK)
            ret = funcList->C_DestroyObject(session, derived);
        else if (derived != CK_INVALID_HANDLE)
            (void)funcList->C_DestroyObject(session, derived);
        if (ret != CKR_OK)
            ctx->failures++;
    }

    if (funcList->C_CloseSession(session) != CKR_OK)
        ctx->failures++;
    return NULL;
}

/* Derives that share one token key run concurrently and all succeed. */
static int test_concurrent_derive_same_key(CK_SESSION_HANDLE session)
{
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &privKeyClass,   sizeof(privKeyClass)    },
        { CKA_KEY_TYPE,    &eccKeyType,     sizeof(eccKeyType)      },
        { CKA_TOKEN,       &ckTrue,         sizeof(ckTrue)          },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)         },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)          },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS,   ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,       ecc_p256_priv,   sizeof(ecc_p256_priv)   },
    };
    pthread_t threads[DERIVE_THREADS];
    DeriveCtx ctx[DERIVE_THREADS];
    int started = 0;
    int failures = 0;
    int i;
    int result = 0;

    ret = funcList->C_CreateObject(session, tmpl,
                                   sizeof(tmpl) / sizeof(*tmpl), &base);
    CHECK_CKR(ret, "create EC token base key");

    for (i = 0; i < DERIVE_THREADS; i++) {
        ctx[i].base = base;
        ctx[i].failures = 0;
        if (pthread_create(&threads[i], NULL, derive_worker, &ctx[i]) != 0)
            break;
        started++;
    }
    if (derive_gate_open(started) != 0)
        failures++;
    for (i = 0; i < started; i++) {
        if (pthread_join(threads[i], NULL) != 0)
            failures++;
        failures += ctx[i].failures;
    }
    if (started != DERIVE_THREADS || failures != 0) {
        fprintf(stderr, "%d of %d concurrent derives failed\n", failures,
                DERIVE_THREADS * DERIVES_PER_THREAD);
        ret = CKR_GENERAL_ERROR;
    }
    CHECK_CKR(ret, "concurrent derives with one token key all succeed");

cleanup:
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    return result;
}
#endif /* EC_DERIVE_THREAD_TEST */

/* Deriving a private key object requires a user login. */
static int test_private_derive_requires_login(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS params;
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_PRIVATE,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &secretLen,      sizeof(secretLen)      },
    };
#ifndef WOLFPKCS11_LEGACY_PRIVATE_FALSE_DEFAULT
    CK_ATTRIBUTE defTmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE_LEN,   &secretLen,      sizeof(secretLen)      },
    };
#endif
    int loggedOut = 0;
    int result = 0;

    ret = funcList->C_Logout(session);
    CHECK_CKR(ret, "C_Logout");
    loggedOut = 1;

    ret = create_ec_base(session, CK_FALSE, CK_TRUE, &base);
    CHECK_CKR(ret, "create public EC base key without login");

    ecdh_params_init(&params, ecc_p256_point, sizeof(ecc_p256_point));
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_CKR(ret, "derive public key without login");
    funcList->C_DestroyObject(session, derived);
    derived = CK_INVALID_HANDLE;

    ret = ecdh_derive_tmpl(session, base, &params, privTmpl,
                           sizeof(privTmpl) / sizeof(*privTmpl), &derived);
    CHECK_RV(ret, CKR_USER_NOT_LOGGED_IN,
             "derive private key without login rejected");

#ifndef WOLFPKCS11_LEGACY_PRIVATE_FALSE_DEFAULT
    ret = ecdh_derive_tmpl(session, base, &params, defTmpl,
                           sizeof(defTmpl) / sizeof(*defTmpl), &derived);
    CHECK_RV(ret, CKR_USER_NOT_LOGGED_IN,
             "derive default-private secret key without login rejected");
#endif

    ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_CKR(ret, "C_Login");
    loggedOut = 0;

    ret = ecdh_derive_tmpl(session, base, &params, privTmpl,
                           sizeof(privTmpl) / sizeof(*privTmpl), &derived);
    CHECK_CKR(ret, "derive private key after login");

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    if (loggedOut &&
            funcList->C_Login(session, CKU_USER, userPin, userPinLen) !=
            CKR_OK) {
        result = -1;
    }
    return result;
}

static CK_RV read_states(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                         CK_BBOOL* alwaysSensitive, CK_BBOOL* neverExtractable)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_ALWAYS_SENSITIVE,  alwaysSensitive,  sizeof(CK_BBOOL) },
        { CKA_NEVER_EXTRACTABLE, neverExtractable, sizeof(CK_BBOOL) },
    };

    return funcList->C_GetAttributeValue(session, obj, tmpl,
                                         sizeof(tmpl) / sizeof(*tmpl));
}

/* A derived key is only always-sensitive / never-extractable when its base
 * key has those historical properties too. */
static int test_derived_states_follow_base(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS params;
    CK_MECHANISM genMech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_BBOOL alwaysSensitive = 0xAA;
    CK_BBOOL neverExtractable = 0xAA;
    byte point[2 * 32 + 3];
    CK_ATTRIBUTE pointAttr = { CKA_EC_POINT, point, sizeof(point) };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS,   ecc_p256_params, sizeof(ecc_p256_params) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)          },
        { CKA_EXTRACTABLE, &ckFalse,        sizeof(ckFalse)         },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)          },
    };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass)  },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType)  },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)          },
        { CKA_EXTRACTABLE, &ckFalse,        sizeof(ckFalse)         },
        { CKA_VALUE_LEN,   &secretLen,      sizeof(secretLen)       },
    };
    int result = 0;

    /* An imported key was never always-sensitive or never-extractable. */
    ret = create_ec_base(session, CK_TRUE, CK_FALSE, &base);
    CHECK_CKR(ret, "create imported EC base key");
    ret = read_states(session, base, &alwaysSensitive, &neverExtractable);
    CHECK_CKR(ret, "read imported base historical flags");
    if (alwaysSensitive != CK_FALSE || neverExtractable != CK_FALSE)
        ret = CKR_GENERAL_ERROR;
    CHECK_CKR(ret, "imported base historical flags are FALSE");

    ecdh_params_init(&params, ecc_p256_point, sizeof(ecc_p256_point));
    ret = ecdh_derive_tmpl(session, base, &params, tmpl,
                           sizeof(tmpl) / sizeof(*tmpl), &derived);
    CHECK_CKR(ret, "derive from imported base key");
    ret = read_states(session, derived, &alwaysSensitive, &neverExtractable);
    CHECK_CKR(ret, "read derived historical flags");
    if (alwaysSensitive != CK_FALSE || neverExtractable != CK_FALSE) {
        fprintf(stderr, "FAIL: derived from imported base: "
                "ALWAYS_SENSITIVE=%d NEVER_EXTRACTABLE=%d, expected FALSE\n",
                (int)alwaysSensitive, (int)neverExtractable);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: derived key does not claim history its base lacks\n");
    test_passed++;
    funcList->C_DestroyObject(session, derived);
    derived = CK_INVALID_HANDLE;
    funcList->C_DestroyObject(session, base);
    base = CK_INVALID_HANDLE;

    /* A generated sensitive, non-extractable key passes its history on. */
    ret = funcList->C_GenerateKeyPair(session, &genMech, pubTmpl,
            sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &pub, &base);
    CHECK_CKR(ret, "generate EC base key");
    ret = funcList->C_GetAttributeValue(session, pub, &pointAttr, 1);
    CHECK_CKR(ret, "read generated EC point");

    ecdh_params_init(&params, point, pointAttr.ulValueLen);
    ret = ecdh_derive_tmpl(session, base, &params, tmpl,
                           sizeof(tmpl) / sizeof(*tmpl), &derived);
    CHECK_CKR(ret, "derive from generated base key");
    ret = read_states(session, derived, &alwaysSensitive, &neverExtractable);
    CHECK_CKR(ret, "read derived historical flags");
    if (alwaysSensitive != CK_TRUE || neverExtractable != CK_TRUE) {
        fprintf(stderr, "FAIL: derived from generated base: "
                "ALWAYS_SENSITIVE=%d NEVER_EXTRACTABLE=%d, expected TRUE\n",
                (int)alwaysSensitive, (int)neverExtractable);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: derived key keeps history its base has\n");
    test_passed++;

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
    return result;
}
#endif /* HAVE_ECC */

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
        dlclose(dlib);
        dlib = NULL;
        return -1;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        dlclose(dlib);
        dlib = NULL;
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
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (ret != CKR_OK)
        return ret;
    if (slotCount == 0)
        return CKR_GENERAL_ERROR;
    slot = slotList[0];
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

static CK_RV pkcs11_setup_token(void)
{
    CK_RV ret;
    unsigned char label[32];
    CK_SESSION_HANDLE soSession;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));
    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &soSession);
    if (ret != CKR_OK)
        return ret;
    ret = funcList->C_Login(soSession, CKU_SO, soPin, soPinLen);
    if (ret == CKR_OK)
        ret = funcList->C_InitPIN(soSession, userPin, userPinLen);
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    return ret;
}

static int ec_derive_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int result = 0;

    printf("\n=== Testing C_DeriveKey with CKM_ECDH1_DERIVE ===\n");

    ret = pkcs11_init();
    CHECK_CKR(ret, "C_Initialize");

    ret = pkcs11_setup_token();
    CHECK_CKR(ret, "token setup");

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession");
    ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_CKR(ret, "C_Login");

#ifdef HAVE_ECC
    if (test_null_kdf_shared_data(session) != 0)
        result = -1;
    if (test_public_data_length_bound(session) != 0)
        result = -1;
    if (test_unsupported_der_length_form(session) != 0)
        result = -1;
    if (test_der_length_within_public_data(session) != 0)
        result = -1;
    if (test_repeated_derive_same_key(session) != 0)
        result = -1;
#ifdef EC_DERIVE_THREAD_TEST
    if (test_concurrent_derive_same_key(session) != 0)
        result = -1;
#endif
    if (test_private_derive_requires_login(session) != 0)
        result = -1;
    if (test_derived_states_follow_base(session) != 0)
        result = -1;
#else
    printf("ECC not available, skipping ECDH derive tests\n");
    test_skipped = 1;
#endif

cleanup:
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();
    return result;
}

#ifdef EC_DERIVE_PERSIST_TEST
static const char persistLabel[] = "ec-derive-persist";

static CK_RV open_user_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;

    ret = pkcs11_init();
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, session);
    }
    if (ret == CKR_OK)
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    return ret;
}

/* Derive a sensitive, non-extractable token key from a generated base key. */
static CK_RV derive_token_key(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_MECHANISM genMech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_ECDH1_DERIVE_PARAMS params;
    byte point[2 * 32 + 3];
    CK_ATTRIBUTE pointAttr = { CKA_EC_POINT, point, sizeof(point) };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS,   ecc_p256_params, sizeof(ecc_p256_params) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)          },
        { CKA_EXTRACTABLE, &ckFalse,        sizeof(ckFalse)         },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)          },
    };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass)  },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType)  },
        { CKA_TOKEN,       &ckTrue,         sizeof(ckTrue)          },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)          },
        { CKA_EXTRACTABLE, &ckFalse,        sizeof(ckFalse)         },
        { CKA_VALUE_LEN,   &secretLen,      sizeof(secretLen)       },
        { CKA_LABEL,       (void*)persistLabel, sizeof(persistLabel) - 1 },
    };

    ret = funcList->C_GenerateKeyPair(session, &genMech, pubTmpl,
            sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
    if (ret == CKR_OK)
        ret = funcList->C_GetAttributeValue(session, pub, &pointAttr, 1);
    if (ret == CKR_OK) {
        ecdh_params_init(&params, point, pointAttr.ulValueLen);
        ret = ecdh_derive_tmpl(session, priv, &params, tmpl,
                               sizeof(tmpl) / sizeof(*tmpl), &derived);
    }
    return ret;
}

/* Historical protection flags of a derived token key survive a reload even
 * when the process ends without C_Finalize. */
static int test_token_derive_states_persist(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ULONG found = 0;
    CK_BBOOL alwaysSensitive = CK_FALSE;
    CK_BBOOL neverExtractable = CK_FALSE;
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_TOKEN, &ckTrue,             sizeof(ckTrue)           },
        { CKA_LABEL, (void*)persistLabel, sizeof(persistLabel) - 1 },
    };
    CK_ATTRIBUTE stateTmpl[] = {
        { CKA_ALWAYS_SENSITIVE,  &alwaysSensitive,  sizeof(CK_BBOOL) },
        { CKA_NEVER_EXTRACTABLE, &neverExtractable, sizeof(CK_BBOOL) },
    };
    pid_t pid;
    int status = 0;
    int result = 0;

    printf("\n=== Testing derived token key state persistence ===\n");

    pid = fork();
    if (pid == 0) {
        /* Exit without C_Finalize so only stores made by the derive count. */
        ret = open_user_session(&session);
        if (ret == CKR_OK)
            ret = derive_token_key(session);
        _exit(ret == CKR_OK ? 0 : 1);
    }
    if (pid < 0)
        ret = CKR_GENERAL_ERROR;
    else if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
             WEXITSTATUS(status) != 0)
        ret = CKR_GENERAL_ERROR;
    else
        ret = CKR_OK;
    CHECK_CKR(ret, "derive token key in child process");

    ret = open_user_session(&session);
    CHECK_CKR(ret, "reopen token");

    ret = funcList->C_FindObjectsInit(session, findTmpl,
                                      sizeof(findTmpl) / sizeof(*findTmpl));
    CHECK_CKR(ret, "C_FindObjectsInit");
    ret = funcList->C_FindObjects(session, &obj, 1, &found);
    if (funcList->C_FindObjectsFinal(session) != CKR_OK && ret == CKR_OK)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK && found != 1)
        ret = CKR_GENERAL_ERROR;
    CHECK_CKR(ret, "find derived token key");

    ret = funcList->C_GetAttributeValue(session, obj, stateTmpl,
                                        sizeof(stateTmpl) / sizeof(*stateTmpl));
    CHECK_CKR(ret, "read derived key historical flags");
    if (alwaysSensitive != CK_TRUE || neverExtractable != CK_TRUE) {
        fprintf(stderr, "FAIL: reloaded derived key ALWAYS_SENSITIVE=%d "
                "NEVER_EXTRACTABLE=%d, expected both TRUE\n",
                (int)alwaysSensitive, (int)neverExtractable);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: reloaded derived key keeps its historical flags\n");
    test_passed++;

cleanup:
    if (obj != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, obj);
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();
    return result;
}
#endif /* EC_DERIVE_PERSIST_TEST */

static void print_results(void)
{
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    if (test_skipped != 0)
        printf("Tests skipped: %d\n", test_skipped);
    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");
}

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif
    (void)argc;
    (void)argv;

    if (ec_derive_test() != 0 && test_failed == 0)
        test_failed++;
#ifdef EC_DERIVE_PERSIST_TEST
    if (test_token_derive_states_persist() != 0 && test_failed == 0)
        test_failed++;
#endif

    print_results();
#ifndef HAVE_ECC
    if (test_failed == 0)
        return 77;
#endif
    return (test_failed == 0) ? 0 : 1;
}
