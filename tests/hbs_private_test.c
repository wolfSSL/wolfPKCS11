/* hbs_private_test.c
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
 * Tests for LMS/HSS keygen and signing (--enable-lms-private), using HSS L1 /
 * LMS SHA256_M32_H5 / LMOTS SHA256_N32_W4: one tree of 32 signatures.
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
    !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_TPM_STORE)

#ifndef _WIN32
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef WOLFPKCS11_DLL_FILENAME
    #ifdef __MACH__
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.dylib"
    #else
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.so"
    #endif
#endif

#define CHECK_CKR(rv, msg)                                                 \
    do {                                                                   \
        if ((rv) != CKR_OK) {                                             \
            fprintf(stderr, "\n%s:%d - %s: %lx - FAIL\n",                  \
                    __FILE__, __LINE__, msg, (unsigned long)(rv));         \
        }                                                                  \
    }                                                                      \
    while (0)

/* Assert that an operation failed with exactly the expected return code. */
#define CHECK_CKR_FAIL(rv, expected, msg)                                  \
    do {                                                                   \
        if ((rv) != (expected)) {                                         \
            fprintf(stderr, "\n%s:%d - %s: got %lx, expected %lx - FAIL\n",\
                    __FILE__, __LINE__, msg, (unsigned long)(rv),          \
                    (unsigned long)(expected));                            \
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
static const char* storeDir = "./store/hbs_priv";

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

/* Scheme under test: HSS L1 / H5 / W4 - a single 32-leaf tree. */
static CK_ULONG hssLevels = 1;
static CK_ULONG hssLmsType = CKL_LMS_SHA256_M32_H5;
static CK_ULONG hssLmotsType = CKL_LMOTS_SHA256_N32_W4;
#define HSS_H5_SIGS 32

static const CK_BYTE testMsg[] = "wolfPKCS11 HSS private-key sign test vector";
#define TEST_MSG_LEN ((CK_ULONG)(sizeof(testMsg) - 1))

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
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        return CKR_GENERAL_ERROR;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: %lx\n",
            (unsigned long)ret);
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: %lx\n",
            (unsigned long)ret);
        return ret;
    }
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
        else {
            fprintf(stderr, "No slots available\n");
            ret = CKR_GENERAL_ERROR;
        }
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

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, strlen(tokenName));
    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    CHECK_CKR(ret, "Init Token");
    return ret;
}

static CK_RV pkcs11_set_user_pin(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
    CHECK_CKR(ret, "Open Session for PIN setup");
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Login as SO");
        if (ret == CKR_OK) {
            ret = funcList->C_InitPIN(session, userPin, userPinLen);
            CHECK_CKR(ret, "Init User PIN");
        }
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    return ret;
}

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    CHECK_CKR(ret, "Open Session");
    if (ret == CKR_OK) {
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login");
    }
    return ret;
}

static void close_session(CK_SESSION_HANDLE session)
{
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
}

/* Remove every wp11_* store artifact so each test starts from a clean token. */
static void cleanup_store(void)
{
#ifndef _WIN32
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
#endif
}

/* Fresh library + token + user PIN + logged-in R/W session. */
static CK_RV fresh_token(CK_SESSION_HANDLE* session)
{
    CK_RV ret;

    cleanup_store();
    ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = pkcs11_init_token();
    if (ret == CKR_OK)
        ret = pkcs11_set_user_pin();
    if (ret == CKR_OK)
        ret = pkcs11_open_session(session);
    return ret;
}

/* Re-open the existing on-disk token (reload path) without wiping the store. */
static CK_RV reopen_token(CK_SESSION_HANDLE* session)
{
    CK_RV ret;

    ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = pkcs11_open_session(session);
    return ret;
}

/* reopen_token without logging a failed login, which tampering tests expect. */
static CK_RV reopen_token_quiet(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    if (ret == CKR_OK)
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    return ret;
}

/* Generate a token-resident HSS keypair with the given scheme parameters. */
static CK_RV gen_hss_key(CK_SESSION_HANDLE session, CK_ULONG levels,
    CK_ULONG lmsType, CK_ULONG lmotsType, CK_BYTE* id, CK_ULONG idLen,
    CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,          &ckTrue,     sizeof(ckTrue)     },
        { CKA_VERIFY,         &ckTrue,     sizeof(ckTrue)     },
        { CKA_ID,             id,          idLen              },
        { CKA_HSS_LEVELS,     &levels,     sizeof(levels)     },
        { CKA_HSS_LMS_TYPE,   &lmsType,    sizeof(lmsType)    },
        { CKA_HSS_LMOTS_TYPE, &lmotsType,  sizeof(lmotsType)  },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_SIGN,  &ckTrue, sizeof(ckTrue) },
        { CKA_ID,    id,      idLen          },
    };

    mech.mechanism = CKM_HSS_KEY_PAIR_GEN;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_GenerateKeyPair(session, &mech,
        pubTmpl, sizeof(pubTmpl) / sizeof(*pubTmpl),
        privTmpl, sizeof(privTmpl) / sizeof(*privTmpl), pub, priv);
    return ret;
}

/* find_by_id without logging a miss. */
static CK_RV find_by_id_quiet(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls,
    CK_BYTE* id, CK_ULONG idLen, CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_ID,    id,   idLen       },
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

/* Find a single token object of the given class by CKA_ID. Reports a miss,
 * so only use it where the object is expected to be present. */
static CK_RV find_by_id(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls,
    CK_BYTE* id, CK_ULONG idLen, CK_OBJECT_HANDLE* obj)
{
    CK_RV ret = find_by_id_quiet(session, cls, id, idLen, obj);

    if (ret != CKR_OK)
        fprintf(stderr, "\nExpected 1 object with the given CKA_ID - FAIL\n");
    return ret;
}

/* Sign testMsg with the two-call length-query protocol; caller frees *sigOut. */
static CK_RV hss_sign(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
    CK_BYTE** sigOut, CK_ULONG* sigLenOut)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_ULONG sigLen = 0;
    CK_BYTE* sig = NULL;

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_SignInit(session, &mech, priv);
    if (ret == CKR_OK) {
        /* First call: NULL buffer -> length query, operation stays active. */
        ret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, NULL,
            &sigLen);
    }
    if (ret == CKR_OK && sigLen == 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        sig = (CK_BYTE*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL)
            ret = CKR_HOST_MEMORY;
    }
    if (ret == CKR_OK)
        ret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &sigLen);
    if (ret == CKR_OK) {
        *sigOut = sig;
        *sigLenOut = sigLen;
    }
    else if (sig != NULL) {
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

static CK_RV hss_verify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub,
    CK_BYTE* sig, CK_ULONG sigLen)
{
    CK_RV ret;
    CK_MECHANISM mech;

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_VerifyInit(session, &mech, pub);
    if (ret == CKR_OK)
        ret = funcList->C_Verify(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            sigLen);
    return ret;
}

static CK_RV get_keys_remaining(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE priv, CK_ULONG* remaining)
{
    CK_ATTRIBUTE a;

    a.type = CKA_HSS_KEYS_REMAINING;
    a.pValue = remaining;
    a.ulValueLen = sizeof(*remaining);
    return funcList->C_GetAttributeValue(session, priv, &a, 1);
}

/* Leaf index of a one-level HSS signature. */
static unsigned long sig_leaf(const CK_BYTE* sig)
{
    return ((unsigned long)sig[4] << 24) | ((unsigned long)sig[5] << 16) |
           ((unsigned long)sig[6] << 8) | (unsigned long)sig[7];
}

/* Keygen, sign with a length query, verify. */
static CK_RV test_keygen_sign_verify(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-ksv";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;

    printf("  keygen -> sign -> verify...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair(CKM_HSS_KEY_PAIR_GEN)");
    }
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "C_Sign(CKM_HSS)");
    }
    if (ret == CKR_OK) {
        ret = hss_verify(session, pub, sig, sigLen);
        CHECK_CKR(ret, "C_Verify(CKM_HSS) of generated signature");
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Durable state survives a reload with no index rollback. */
static CK_RV test_reload_no_rollback(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-reload";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_ULONG remainingBefore = 0, remainingAfterReload = 0, remainingFinal = 0;
    int i;

    printf("  sign N, reload, confirm no rollback...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    /* Sign three times before the reload. */
    for (i = 0; ret == CKR_OK && i < 3; i++) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "pre-reload C_Sign");
        if (ret == CKR_OK) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remainingBefore);
        CHECK_CKR(ret, "keys-remaining before reload");
    }
    /* Force a reload from disk. */
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK) {
        printf("    --- reloading token from disk ---\n");
        ret = reopen_token(&session);
    }
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remainingAfterReload);
        CHECK_CKR(ret, "keys-remaining after reload");
    }
    /* The counter must not have rolled back across the reload. */
    if (ret == CKR_OK && remainingAfterReload != remainingBefore) {
        fprintf(stderr, "\nOTS index rolled back on reload: before=%lu "
            "after=%lu - FAIL\n", (unsigned long)remainingBefore,
            (unsigned long)remainingAfterReload);
        ret = CKR_GENERAL_ERROR;
    }
    /* A post-reload signature must continue decrementing and still verify. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "post-reload C_Sign");
    }
    if (ret == CKR_OK) {
        ret = hss_verify(session, pub, sig, sigLen);
        CHECK_CKR(ret, "post-reload C_Verify");
    }
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remainingFinal);
        CHECK_CKR(ret, "keys-remaining after post-reload sign");
    }
    if (ret == CKR_OK && remainingFinal != remainingAfterReload - 1) {
        fprintf(stderr, "\nCounter did not advance after reload: %lu -> %lu "
            "- FAIL\n", (unsigned long)remainingAfterReload,
            (unsigned long)remainingFinal);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Keygen template validation. */
static CK_RV gen_expect(CK_SESSION_HANDLE session, CK_ATTRIBUTE* pubTmpl,
    CK_ULONG pubCount, CK_ATTRIBUTE* privTmpl, CK_ULONG privCount,
    CK_VOID_PTR param, CK_ULONG paramLen, CK_RV expected, const char* msg)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;

    mech.mechanism = CKM_HSS_KEY_PAIR_GEN;
    mech.pParameter = param;
    mech.ulParameterLen = paramLen;

    ret = funcList->C_GenerateKeyPair(session, &mech, pubTmpl, pubCount,
        privTmpl, privCount, &pub, &priv);
    CHECK_CKR_FAIL(ret, expected, msg);
    if (ret == CKR_OK) {
        /* Should not have succeeded; clean up so the test stays isolated. */
        funcList->C_DestroyObject(session, pub);
        funcList->C_DestroyObject(session, priv);
        return CKR_GENERAL_ERROR;
    }
    return (ret == expected) ? CKR_OK : ret;
}

static CK_RV test_keygen_negative_templates(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_ULONG dummyParam = 0;
    CK_ULONG badType = 0x00000099UL;
    CK_ULONG shortLevels = 1;
    CK_BYTE id[] = "hss-neg";

    /* Fully valid templates, mutated per-case below. */
    CK_ATTRIBUTE pubOk[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     &hssLevels,    sizeof(hssLevels)    },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
    };
    CK_ATTRIBUTE privOk[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_ID,    id,      sizeof(id) - 1 },
    };
    /* CKA_TOKEN=FALSE on the private arm. */
    CK_ATTRIBUTE privTokFalse[] = {
        { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
        { CKA_ID,    id,       sizeof(id) - 1  },
    };
    /* Missing CKA_HSS_LMS_TYPE / LMOTS_TYPE. */
    CK_ATTRIBUTE pubIncomplete[] = {
        { CKA_TOKEN,      &ckTrue,    sizeof(ckTrue)    },
        { CKA_HSS_LEVELS, &hssLevels, sizeof(hssLevels) },
    };
    /* Wrong-sized CKA_HSS_LEVELS. */
    CK_ATTRIBUTE pubBadSize[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     &shortLevels,  1                    },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
    };
    /* Private arm claims to be an RSA key. */
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_ATTRIBUTE privRsa[] = {
        { CKA_TOKEN,    &ckTrue,  sizeof(ckTrue)  },
        { CKA_KEY_TYPE, &rsaType, sizeof(rsaType) },
    };
    /* CKA_HSS_LEVELS that is only valid once truncated to 32 bits. */
    CK_ULONG wideLevels = (CK_ULONG)1;
    CK_ATTRIBUTE pubWideLevels[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     &wideLevels,   sizeof(wideLevels)   },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
    };
    CK_ATTRIBUTE privCopyable[] = {
        { CKA_TOKEN,    &ckTrue, sizeof(ckTrue) },
        { CKA_COPYABLE, &ckTrue, sizeof(ckTrue) },
    };
    /* CKA_HSS_LEVELS on both templates with different values. */
    CK_ULONG otherLevels = 2;
    CK_ATTRIBUTE privConflict[] = {
        { CKA_TOKEN,      &ckTrue,      sizeof(ckTrue)      },
        { CKA_HSS_LEVELS, &otherLevels, sizeof(otherLevels) },
    };
    /* Oversized CKA_HSS_LEVELS on both templates, equal in the first word. */
    CK_ULONG longLevelsPub[2] = { 1, 2 };
    CK_ULONG longLevelsPriv[2] = { 1, 3 };
    CK_ATTRIBUTE pubLongLevels[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     longLevelsPub, sizeof(longLevelsPub) },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
    };
    CK_ATTRIBUTE privLongLevels[] = {
        { CKA_TOKEN,      &ckTrue,        sizeof(ckTrue)         },
        { CKA_HSS_LEVELS, longLevelsPriv, sizeof(longLevelsPriv) },
    };
    /* Invalid LMS type value. */
    CK_ATTRIBUTE pubBadType[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     &hssLevels,    sizeof(hssLevels)    },
        { CKA_HSS_LMS_TYPE,   &badType,      sizeof(badType)      },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
    };

    printf("  keygen template validation...\n");
    ret = fresh_token(&session);

    /* Non-NULL mechanism parameter -> CKR_MECHANISM_PARAM_INVALID. */
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubOk, 4, privOk, 2, &dummyParam,
            sizeof(dummyParam), CKR_MECHANISM_PARAM_INVALID,
            "non-NULL mechanism parameter");
    }
    /* CKA_TOKEN=FALSE -> CKR_TEMPLATE_INCONSISTENT. */
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubOk, 4, privTokFalse, 2, NULL, 0,
            CKR_TEMPLATE_INCONSISTENT, "CKA_TOKEN=FALSE on private key");
    }
    /* Missing scheme attributes -> CKR_TEMPLATE_INCOMPLETE. */
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubIncomplete, 2, privOk, 2, NULL, 0,
            CKR_TEMPLATE_INCOMPLETE, "missing CKA_HSS_LMS/LMOTS_TYPE");
    }
    /* Wrong-sized attribute -> CKR_ATTRIBUTE_VALUE_INVALID. */
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubBadSize, 4, privOk, 2, NULL, 0,
            CKR_ATTRIBUTE_VALUE_INVALID, "wrong-sized CKA_HSS_LEVELS");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubBadType, 4, privOk, 2, NULL, 0,
            CKR_ATTRIBUTE_VALUE_INVALID, "invalid CKA_HSS_LMS_TYPE");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubOk, 4, privRsa, 2, NULL, 0,
            CKR_TEMPLATE_INCONSISTENT, "CKA_KEY_TYPE=CKK_RSA on private key");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubOk, 4, privCopyable, 2, NULL, 0,
            CKR_TEMPLATE_INCONSISTENT, "CKA_COPYABLE=TRUE on private key");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubOk, 4, privConflict, 2, NULL, 0,
            CKR_TEMPLATE_INCONSISTENT, "CKA_HSS_LEVELS differs per template");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubLongLevels, 4, privLongLevels, 2, NULL,
            0, CKR_ATTRIBUTE_VALUE_INVALID,
            "oversized CKA_HSS_LEVELS on both templates");
    }
    if (ret == CKR_OK && sizeof(CK_ULONG) > 4) {
        wideLevels = (CK_ULONG)1 | (((CK_ULONG)1 << 16) << 16);
        ret = gen_expect(session, pubWideLevels, 4, privOk, 2, NULL, 0,
            CKR_ATTRIBUTE_VALUE_INVALID, "CKA_HSS_LEVELS above 32 bits");
    }

    close_session(session);
    pkcs11_final();
    return ret;
}

/* CKA_HSS_KEYS_REMAINING on a private key. */
static CK_RV test_keys_remaining_private(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-remain";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_ULONG remaining = 0, remainingAfter = 0;
    CK_ATTRIBUTE a;
    CK_BYTE small = 0;

    printf("  CKA_HSS_KEYS_REMAINING on private key...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    /* Size query: NULL buffer must report sizeof(CK_ULONG). */
    if (ret == CKR_OK) {
        a.type = CKA_HSS_KEYS_REMAINING;
        a.pValue = NULL;
        a.ulValueLen = 0;
        ret = funcList->C_GetAttributeValue(session, priv, &a, 1);
        CHECK_CKR(ret, "keys-remaining size query");
        if (ret == CKR_OK && a.ulValueLen != sizeof(CK_ULONG)) {
            fprintf(stderr, "\nkeys-remaining size query returned %lu - FAIL\n",
                (unsigned long)a.ulValueLen);
            ret = CKR_GENERAL_ERROR;
        }
    }
    /* Value must equal the full 2^(levels*height) tree size before signing. */
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remaining);
        CHECK_CKR(ret, "keys-remaining value");
    }
    if (ret == CKR_OK && remaining != HSS_H5_SIGS) {
        fprintf(stderr, "\nInitial keys-remaining %lu, expected %d - FAIL\n",
            (unsigned long)remaining, HSS_H5_SIGS);
        ret = CKR_GENERAL_ERROR;
    }
    /* Too-small buffer must be reported as CKR_BUFFER_TOO_SMALL. */
    if (ret == CKR_OK) {
        a.type = CKA_HSS_KEYS_REMAINING;
        a.pValue = &small;
        a.ulValueLen = sizeof(small);
        ret = funcList->C_GetAttributeValue(session, priv, &a, 1);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "keys-remaining small buffer");
        ret = (ret == CKR_BUFFER_TOO_SMALL) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    /* The count decrements by one after a signature. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "C_Sign");
    }
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remainingAfter);
        CHECK_CKR(ret, "keys-remaining after sign");
    }
    if (ret == CKR_OK && remainingAfter != remaining - 1) {
        fprintf(stderr, "\nkeys-remaining did not decrement: %lu -> %lu "
            "- FAIL\n", (unsigned long)remaining, (unsigned long)remainingAfter);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Private-key import is rejected. */
static CK_RV test_import_value_rejected(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_HSS;
    CK_BYTE fakeValue[64];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,          &privClass,    sizeof(privClass)    },
        { CKA_KEY_TYPE,       &keyType,      sizeof(keyType)      },
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_SIGN,           &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     &hssLevels,    sizeof(hssLevels)    },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
        { CKA_VALUE,          fakeValue,     sizeof(fakeValue)    },
    };

    printf("  private-key import with CKA_VALUE is rejected...\n");
    XMEMSET(fakeValue, 0xAB, sizeof(fakeValue));
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        CK_RV cret = funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &obj);
        if (cret == CKR_OK) {
            fprintf(stderr, "\nValue-carrying HSS private-key import accepted "
                "- FAIL\n");
            funcList->C_DestroyObject(session, obj);
            ret = CKR_GENERAL_ERROR;
        }
        else {
            printf("    rejected with %lx (expected)\n", (unsigned long)cret);
        }
    }
    /* Without CKA_VALUE, as a session object. */
    if (ret == CKR_OK) {
        CK_RV cret;

        tmpl[2].pValue = &ckFalse;
        cret = funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl) - 1, &obj);
        CHECK_CKR_FAIL(cret, CKR_ATTRIBUTE_VALUE_INVALID,
            "empty HSS private-key import");
        if (cret == CKR_OK)
            funcList->C_DestroyObject(session, obj);
        if (cret != CKR_ATTRIBUTE_VALUE_INVALID)
            ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A spent key returns CKR_KEY_EXHAUSTED. */
static CK_RV test_exhaustion_poison(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-exhaust";
    CK_MECHANISM mech;
    CK_BYTE sig[4096];
    CK_ULONG sigLen;
    CK_ULONG initialRemaining = 0;
    int successes = 0;
    int i;

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    printf("  key exhaustion reports CKR_KEY_EXHAUSTED...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &initialRemaining);
        CHECK_CKR(ret, "initial keys-remaining");
    }
    /* Sign until the tree is exhausted. Each failed C_Sign must have cleared
     * the operation, so the next C_SignInit succeeds. */
    for (i = 0; ret == CKR_OK && i < HSS_H5_SIGS + 4; i++) {
        CK_RV sret = funcList->C_SignInit(session, &mech, priv);
        if (sret != CKR_OK) {
            fprintf(stderr, "\nC_SignInit failed at iter %d: %lx - FAIL\n",
                i, (unsigned long)sret);
            ret = CKR_GENERAL_ERROR;
            break;
        }
        sigLen = sizeof(sig);
        sret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &sigLen);
        if (sret == CKR_OK) {
            successes++;
        }
        else {
            printf("    exhausted after %d signatures (first failure %lx)\n",
                successes, (unsigned long)sret);
            CHECK_CKR_FAIL(sret, CKR_KEY_EXHAUSTED, "first spent-key C_Sign");
            if (sret != CKR_KEY_EXHAUSTED)
                ret = CKR_GENERAL_ERROR;
            sret = funcList->C_SignInit(session, &mech, priv);
            CHECK_CKR(sret, "C_SignInit after exhaustion");
            if (sret == CKR_OK) {
                sigLen = sizeof(sig);
                sret = funcList->C_Sign(session, (CK_BYTE*)testMsg,
                    TEST_MSG_LEN, sig, &sigLen);
                CHECK_CKR_FAIL(sret, CKR_KEY_EXHAUSTED, "spent-key C_Sign");
                if (sret != CKR_KEY_EXHAUSTED)
                    ret = CKR_GENERAL_ERROR;
            }
            else {
                ret = CKR_GENERAL_ERROR;
            }
            break;
        }
    }
    if (ret == CKR_OK && successes != (int)initialRemaining) {
        fprintf(stderr, "\nSigned %d times, keys-remaining said %lu - FAIL\n",
            successes, (unsigned long)initialRemaining);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

#ifndef _WIN32
/* Locate the single HSS private key record, which holds the sealed state. */
static CK_RV find_key_record(char* path, size_t pathLen)
{
    DIR* d;
    struct dirent* e;
    CK_RV ret = CKR_OBJECT_HANDLE_INVALID;
    const char* prefix = "wp11_hsskey_priv_";

    d = opendir(storeDir);
    if (d == NULL)
        return CKR_GENERAL_ERROR;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, strlen(prefix)) == 0) {
            snprintf(path, pathLen, "%s/%s", storeDir, e->d_name);
            ret = CKR_OK;
            break;
        }
    }
    closedir(d);
    return ret;
}

/* C_DestroyObject removes the key record, and the state with it. */
static CK_RV test_destroy_removes_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-destroy";
    char recPath[512];
    FILE* f;

    printf("  C_DestroyObject removes the key record...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    if (ret == CKR_OK) {
        ret = find_key_record(recPath, sizeof(recPath));
        CHECK_CKR(ret, "locate key record after keygen");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, priv);
        CHECK_CKR(ret, "C_DestroyObject(private key)");
    }
    if (ret == CKR_OK) {
        f = fopen(recPath, "rb");
        if (f != NULL) {
            fclose(f);
            fprintf(stderr, "\nKey record still present after destroy: %s "
                "- FAIL\n", recPath);
            ret = CKR_GENERAL_ERROR;
        }
        else {
            printf("    key record removed\n");
        }
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

static int count_store_files(const char* prefix)
{
    DIR* d;
    struct dirent* e;
    int cnt = 0;

    d = opendir(storeDir);
    if (d == NULL)
        return -1;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, strlen(prefix)) == 0)
            cnt++;
    }
    closedir(d);
    return cnt;
}

/* Destroying a private key that is not the newest object moves the newest
 * object into its store id; only the destroyed key's record goes. */
static CK_RV test_destroy_older_key_removes_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubA = CK_INVALID_HANDLE, privA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubB = CK_INVALID_HANDLE, privB = CK_INVALID_HANDLE;
    CK_BYTE idA[] = "hss-older";
    CK_BYTE idB[] = "hss-newer";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    int cnt;

    printf("  destroying an older private key removes only its state...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idA, sizeof(idA) - 1, &pubA, &privA);
        CHECK_CKR(ret, "keygen A");
    }
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pubB, &privB);
        CHECK_CKR(ret, "keygen B");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, privA);
        CHECK_CKR(ret, "C_DestroyObject(private key A)");
    }
    if (ret == CKR_OK) {
        cnt = count_store_files("wp11_hsskey_priv_");
        if (cnt != 1) {
            fprintf(stderr, "\n%d private key records after destroy, "
                "expected 1 - FAIL\n", cnt);
            ret = CKR_GENERAL_ERROR;
        }
    }
    close_session(session);
    pkcs11_final();

    if (ret == CKR_OK) {
        ret = reopen_token(&session);
        CHECK_CKR(ret, "reopen after destroying key A");
    }
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_PRIVATE_KEY, idB, sizeof(idB) - 1,
            &privB);
        CHECK_CKR(ret, "private key B survived");
    }
    if (ret == CKR_OK) {
        ret = hss_sign(session, privB, &sig, &sigLen);
        CHECK_CKR(ret, "sign with key B");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
        if (ret == CKR_OK)
            printf("    key B still signs\n");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A tampered state is detected on reload; the key stays visible and can be
 * destroyed, but does not sign. */
static CK_RV test_state_tamper_detected(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-tamper";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    char recPath[512];
    FILE* f;
    long fsize;
    int flipByte;

    printf("  tampered state is detected on reload...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    /* Sign once so a real advanced state is on disk before we tamper it. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "C_Sign before tamper");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    /* Force everything to disk, then flip a ciphertext byte near the end. */
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK) {
        f = fopen(recPath, "rb+");
        if (f == NULL)
            ret = CKR_GENERAL_ERROR;
        else {
            CK_BYTE b = 0;
            fseek(f, 0, SEEK_END);
            fsize = ftell(f);
            flipByte = (int)(fsize > 4 ? fsize - 4 : 0);
            fseek(f, flipByte, SEEK_SET);
            if (fread(&b, 1, 1, f) == 1) {
                b ^= 0xFF;
                fseek(f, flipByte, SEEK_SET);
                fwrite(&b, 1, 1, f);
            }
            else {
                ret = CKR_GENERAL_ERROR;
            }
            fclose(f);
        }
    }
    if (ret == CKR_OK) {
        ret = reopen_token_quiet(&session);
        CHECK_CKR(ret, "login with a tampered key on the token");
    }
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
        CHECK_CKR(ret, "tampered key is visible");
    }
    if (ret == CKR_OK) {
        CK_RV sret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR_FAIL(sret, CKR_DEVICE_ERROR, "sign with a tampered state");
        if (sig != NULL)
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sret != CKR_DEVICE_ERROR)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, priv);
        CHECK_CKR(ret, "destroy the tampered key");
    }
    if (ret == CKR_OK && count_store_files("wp11_hsskey_priv_") != 0) {
        fprintf(stderr, "\ntampered key record left after destroy - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A failed state write releases no signature, the next sign reloads the
 * stored state, and no leaf of a released signature is used again. */
static CK_RV test_write_failure_poison(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-wfail";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0, before = 0, after = 0;
    unsigned long baseLeaf = 0;
    struct stat dirStat;
    int dirModeSaved = 0;
    int skipInjection = 0;

    printf("  a key recovers after a failed state write...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    /* One good signature establishes a durable baseline index on disk. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "baseline sign");
        if (sig != NULL) {
            baseLeaf = sig_leaf(sig);
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &before);
    /* Root ignores the read-only directory used to fail the write. */
    if (ret == CKR_OK && geteuid() == 0) {
        printf("    skipping write-failure injection (running as root)\n");
        skipInjection = 1;
    }
    if (ret == CKR_OK && !skipInjection) {
        /* Capture the real mode so it can be put back exactly. */
        if (stat(storeDir, &dirStat) != 0 || chmod(storeDir, 0500) != 0)
            ret = CKR_GENERAL_ERROR;
        else
            dirModeSaved = 1;
    }
    if (ret == CKR_OK && !skipInjection) {
        sret = hss_sign(session, priv, &sig, &sigLen);
        if (sret == CKR_OK) {
            fprintf(stderr, "\nsigned despite an unwritable store - FAIL\n");
            if (sig != NULL) {
                XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                sig = NULL;
            }
            ret = CKR_GENERAL_ERROR;
        }
        else {
            printf("    write-failed sign refused: %lx\n", (unsigned long)sret);
        }
    }
    if (dirModeSaved)
        (void)chmod(storeDir, dirStat.st_mode);   /* restore, even on failure */
    if (skipInjection) {
        close_session(session);
        pkcs11_final();
        return ret;
    }
    /* The next sign reloads the stored state and takes the leaf after the
     * baseline, which the failed sign never released. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "sign after the failed write");
    }
    if (ret == CKR_OK && sig_leaf(sig) != baseLeaf + 1) {
        fprintf(stderr, "\nsigned leaf %lu after baseline %lu - FAIL\n",
            sig_leaf(sig), baseLeaf);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL) {
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        sig = NULL;
    }
    /* A reload continues from the last stored index. */
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &after);
    if (ret == CKR_OK && after != before - 1) {
        fprintf(stderr, "\n%lu left after %lu and one more signature - "
            "FAIL\n", (unsigned long)after, (unsigned long)before);
        ret = CKR_GENERAL_ERROR;
    }
    /* And it still signs correctly from the recovered state. */
    if (ret == CKR_OK)
        ret = hss_sign(session, priv, &sig, &sigLen);
    if (ret == CKR_OK)
        ret = hss_verify(session, pub, sig, sigLen);
    CHECK_CKR(ret, "post-recovery sign/verify");
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A forked child signs and exits without C_Finalize; its index is never
 * reused. */
static CK_RV test_crash_durability(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-crash";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0, before = 0, after = 0;
    pid_t pid;
    int status = 0;

    printf("  per-sign durability survives an unclean exit (fork)...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &before);
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret != CKR_OK)
        return ret;

    pid = fork();
    if (pid == 0) {
        /* Child: fresh process. Reload, sign once (durable), then hard-exit
         * with no C_Finalize, simulating a crash right after a signature. */
        CK_SESSION_HANDLE cs = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE cp = CK_INVALID_HANDLE;
        CK_BYTE* csig = NULL;
        CK_ULONG cslen = 0;
        CK_RV cret;

        cret = reopen_token(&cs);
        if (cret == CKR_OK)
            cret = find_by_id(cs, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &cp);
        if (cret == CKR_OK)
            cret = hss_sign(cs, cp, &csig, &cslen);
        _exit(cret == CKR_OK ? 0 : 1);
    }
    if (pid < 0)
        return CKR_GENERAL_ERROR;
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
        fprintf(stderr, "\nchild sign failed (status %d) - FAIL\n", status);
        return CKR_GENERAL_ERROR;
    }

    /* The child's signature advanced the durable state by exactly one. */
    ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &after);
    if (ret == CKR_OK && after != before - 1) {
        fprintf(stderr, "\ncrash durability: remaining %lu -> %lu, expected a "
            "drop of 1 - FAIL\n", (unsigned long)before, (unsigned long)after);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = hss_sign(session, priv, &sig, &sigLen);
    if (ret == CKR_OK)
        ret = hss_verify(session, pub, sig, sigLen);
    CHECK_CKR(ret, "post-crash sign/verify");
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Key record corruption matrix. */
#define CORRUPT_TRUNCATE 0
#define CORRUPT_MAGIC    1
#define CORRUPT_PARAM    2
#define CORRUPT_TAG      3
#define CORRUPT_DIGEST   4

static CK_RV corrupt_state_and_check(const char* label, int type)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-corrupt";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    char recPath[512];
    FILE* f;
    long fsize = 0, off;
    CK_BYTE b = 0;

    printf("    [%s]...\n", label);
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret != CKR_OK)
        return ret;

    if (type == CORRUPT_TRUNCATE) {
        f = fopen(recPath, "rb");
        if (f == NULL)
            return CKR_GENERAL_ERROR;
        fseek(f, 0, SEEK_END);
        fsize = ftell(f);
        fclose(f);
        if (truncate(recPath, fsize > 8 ? fsize - 8 : 0) != 0)
            return CKR_GENERAL_ERROR;
    }
    else {
        f = fopen(recPath, "rb+");
        if (f == NULL)
            return CKR_GENERAL_ERROR;
        fseek(f, 0, SEEK_END);
        fsize = ftell(f);
        /* The record follows a 4-byte length; the shell follows its own. */
        if (type == CORRUPT_MAGIC) {
            off = 8;
        }
        else if (type == CORRUPT_PARAM) {
            off = 16;
        }
        else if (type == CORRUPT_DIGEST) {
            /* Last byte of the policy digest, after the kind and its length. */
            CK_BYTE l[4];

            fseek(f, 4, SEEK_SET);
            if (fread(l, 1, 4, f) != 4) {
                fclose(f);
                return CKR_GENERAL_ERROR;
            }
            off = 8 + (long)(((CK_ULONG)l[0] << 24) | ((CK_ULONG)l[1] << 16) |
                ((CK_ULONG)l[2] << 8) | l[3]) + 8 + 32 - 1;
        }
        else {
            off = fsize - 1;
        }
        fseek(f, off, SEEK_SET);
        if (fread(&b, 1, 1, f) == 1) {
            b ^= 0xFF;
            fseek(f, off, SEEK_SET);
            fwrite(&b, 1, 1, f);
        }
        else {
            fclose(f);
            return CKR_GENERAL_ERROR;
        }
        fclose(f);
    }

    /* The key stays visible and can be destroyed, but does not sign. */
    ret = reopen_token_quiet(&session);
    CHECK_CKR(ret, "login after corruption");
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
        CHECK_CKR(ret, "corrupted key is visible");
    }
    if (ret == CKR_OK) {
        sret = hss_sign(session, priv, &sig, &sigLen);
        if (sig != NULL)
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        CHECK_CKR_FAIL(sret, CKR_DEVICE_ERROR, label);
        if (sret != CKR_DEVICE_ERROR)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, priv);
        CHECK_CKR(ret, "destroy the corrupted key");
    }
    if (ret == CKR_OK && count_store_files("wp11_hsskey_priv_") != 0) {
        fprintf(stderr, "\n[%s] key record left after destroy - FAIL\n",
            label);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

static CK_RV test_corruption_matrix(void)
{
    CK_RV ret;

    printf("  on-disk state corruption matrix...\n");
    ret = corrupt_state_and_check("truncated", CORRUPT_TRUNCATE);
    if (ret == CKR_OK)
        ret = corrupt_state_and_check("bad magic", CORRUPT_MAGIC);
    if (ret == CKR_OK)
        ret = corrupt_state_and_check("bad scheme param", CORRUPT_PARAM);
    if (ret == CKR_OK)
        ret = corrupt_state_and_check("flipped GCM tag", CORRUPT_TAG);
    if (ret == CKR_OK)
        ret = corrupt_state_and_check("flipped policy digest",
            CORRUPT_DIGEST);
    return ret;
}
#endif /* !_WIN32 */

/* Parameter matrix. */
typedef struct {
    const char* name;
    CK_ULONG levels;
    CK_ULONG lms;
    CK_ULONG lmots;
    CK_ULONG capacity;   /* 2^(levels*height) */
    int fast;            /* 1 = part of the default fast subset */
} HssParamSet;

static const HssParamSet paramSets[] = {
    { "L1/H5/W1",  1, CKL_LMS_SHA256_M32_H5,  CKL_LMOTS_SHA256_N32_W1,   32, 0 },
    { "L1/H5/W2",  1, CKL_LMS_SHA256_M32_H5,  CKL_LMOTS_SHA256_N32_W2,   32, 0 },
    { "L1/H5/W4",  1, CKL_LMS_SHA256_M32_H5,  CKL_LMOTS_SHA256_N32_W4,   32, 1 },
    { "L1/H5/W8",  1, CKL_LMS_SHA256_M32_H5,  CKL_LMOTS_SHA256_N32_W8,   32, 0 },
    { "L1/H10/W4", 1, CKL_LMS_SHA256_M32_H10, CKL_LMOTS_SHA256_N32_W4, 1024, 0 },
    { "L2/H5/W4",  2, CKL_LMS_SHA256_M32_H5,  CKL_LMOTS_SHA256_N32_W4, 1024, 1 },
};

/* keygen -> sign x2 -> verify -> reload -> confirm counter preserved -> sign
 * -> verify, for one parameter set. Each set gets a fresh token. */
static CK_RV run_param_set(const HssParamSet* ps)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-param";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0, remaining = 0, remaining2 = 0;
    int i;

    printf("    [%s] keygen/sign/verify/reload...\n", ps->name);
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, ps->levels, ps->lms, ps->lmots,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "param-set keygen");
    }
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remaining);
        CHECK_CKR(ret, "param-set keys-remaining");
    }
    if (ret == CKR_OK && remaining != ps->capacity) {
        fprintf(stderr, "\n[%s] capacity %lu, expected %lu - FAIL\n", ps->name,
            (unsigned long)remaining, (unsigned long)ps->capacity);
        ret = CKR_GENERAL_ERROR;
    }
    for (i = 0; ret == CKR_OK && i < 2; i++) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        if (ret == CKR_OK)
            ret = hss_verify(session, pub, sig, sigLen);
        CHECK_CKR(ret, "param-set pre-reload sign/verify");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    /* Reload and confirm the counter survived (capacity - 2 signs). */
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &remaining2);
    if (ret == CKR_OK && remaining2 != ps->capacity - 2) {
        fprintf(stderr, "\n[%s] post-reload remaining %lu, expected %lu "
            "- FAIL\n", ps->name, (unsigned long)remaining2,
            (unsigned long)(ps->capacity - 2));
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = hss_sign(session, priv, &sig, &sigLen);
    if (ret == CKR_OK)
        ret = hss_verify(session, pub, sig, sigLen);
    CHECK_CKR(ret, "param-set post-reload sign/verify");
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

static CK_RV test_param_matrix(void)
{
    CK_RV ret = CKR_OK;
    int full = 0, i, n;

#ifndef WOLFPKCS11_NO_ENV
    if (XGETENV("WOLFPKCS11_HSS_FULL_MATRIX") != NULL)
        full = 1;
#endif
    n = (int)(sizeof(paramSets) / sizeof(paramSets[0]));
    printf("  parameter matrix (%s)...\n", full ? "full" : "fast subset");
    for (i = 0; ret == CKR_OK && i < n; i++) {
        if (!full && !paramSets[i].fast)
            continue;
        ret = run_param_set(&paramSets[i]);
    }
    if (ret == CKR_OK && !full) {
        printf("    (set WOLFPKCS11_HSS_FULL_MATRIX=1 for W1/W2/W8 and H10)\n");
    }
    return ret;
}

/* L2/H5: signing across the end of the first lower subtree, with a reload on
 * each side. */
static CK_RV test_multilevel_rollover(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-rollover";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0, remaining = 0;
    const int crossAt = 32;   /* lower-subtree size, 2^5 */
    const int total = 36;     /* a few signatures past the boundary */
    int i;

    printf("  multi-level (L2/H5) subtree rollover...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, 2, CKL_LMS_SHA256_M32_H5,
            CKL_LMOTS_SHA256_N32_W4, id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "L2 keygen");
    }
    for (i = 0; ret == CKR_OK && i < total; i++) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        if (ret == CKR_OK)
            ret = hss_verify(session, pub, sig, sigLen);
        CHECK_CKR(ret, "rollover sign/verify");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
        /* Reload right after crossing into the second subtree. */
        if (ret == CKR_OK && i == crossAt) {
            printf("    --- reload straddling the subtree boundary ---\n");
            close_session(session);
            session = CK_INVALID_HANDLE;
            pkcs11_final();
            ret = reopen_token(&session);
            if (ret == CKR_OK)
                ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1,
                    &priv);
            if (ret == CKR_OK)
                ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1,
                    &pub);
            CHECK_CKR(ret, "reload across boundary");
        }
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &remaining);
    if (ret == CKR_OK && remaining != (CK_ULONG)(1024 - total)) {
        fprintf(stderr, "\nrollover: remaining %lu, expected %d - FAIL\n",
            (unsigned long)remaining, 1024 - total);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Destroying the public key moves the private key's records to another id; its
 * state must survive. */
static CK_RV test_destroy_sibling_keeps_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-sibling";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;

    printf("  destroying the public key keeps the private state...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    /* One signature so the on-disk state is past the genesis index. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "baseline sign");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, pub);
        CHECK_CKR(ret, "C_DestroyObject(public)");
    }
    close_session(session);
    pkcs11_final();

    /* Reload the token: the private key must still decode and sign. */
    if (ret == CKR_OK) {
        ret = reopen_token(&session);
        CHECK_CKR(ret, "reopen after destroying the public key");
    }
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
        CHECK_CKR(ret, "private key survived");
    }
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "sign after the sibling was destroyed");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
        if (ret == CKR_OK)
            printf("    private key still signs\n");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A spent key does not stop C_Login, stays visible, refuses to sign and can be
 * destroyed. */
static CK_RV test_exhausted_key_login(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-spent";
    CK_BYTE aesId[] = "aes-bystander";
    CK_MECHANISM mech;
    CK_BYTE sig[4096];
    CK_ULONG sigLen;
    int i;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BYTE aesKey[32] = { 0 };
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_ID,       aesId,        sizeof(aesId) - 1   },
        { CKA_VALUE,    aesKey,       sizeof(aesKey)      },
    };

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    printf("  an exhausted key does not break login for the token...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    /* An unrelated token object that must remain reachable afterwards. */
    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, aesTmpl,
            sizeof(aesTmpl) / sizeof(*aesTmpl), &aes);
        CHECK_CKR(ret, "create bystander AES key");
    }
    /* Spend the whole tree. */
    for (i = 0; ret == CKR_OK && i < HSS_H5_SIGS + 4; i++) {
        sret = funcList->C_SignInit(session, &mech, priv);
        if (sret != CKR_OK)
            break;
        sigLen = sizeof(sig);
        sret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &sigLen);
        if (sret != CKR_OK)
            break;
    }
    close_session(session);
    pkcs11_final();

    /* The whole point: login must still work. */
    if (ret == CKR_OK) {
        ret = reopen_token(&session);
        CHECK_CKR(ret, "C_Login with an exhausted HSS key on the token");
    }
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_SECRET_KEY, aesId, sizeof(aesId) - 1,
            &aes);
        CHECK_CKR(ret, "bystander key still reachable");
    }
    if (ret == CKR_OK) {
        printf("    login succeeded, other objects reachable\n");
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
        CHECK_CKR(ret, "spent key is visible");
    }
    if (ret == CKR_OK) {
        CK_ULONG left = 1;

        ret = get_keys_remaining(session, priv, &left);
        CHECK_CKR(ret, "keys remaining of the spent key");
        if (ret == CKR_OK && left != 0) {
            fprintf(stderr, "\nspent key reports %lu left - FAIL\n",
                (unsigned long)left);
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (ret == CKR_OK) {
        sret = funcList->C_SignInit(session, &mech, priv);
        if (sret == CKR_OK) {
            sigLen = sizeof(sig);
            sret = funcList->C_Sign(session, (CK_BYTE*)testMsg,
                TEST_MSG_LEN, sig, &sigLen);
        }
        CHECK_CKR_FAIL(sret, CKR_KEY_EXHAUSTED, "spent-key sign");
        if (sret != CKR_KEY_EXHAUSTED)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, priv);
        CHECK_CKR(ret, "destroy the spent key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, pub);
        CHECK_CKR(ret, "destroy the spent key's public key");
    }
    /* The bystander key must still be usable and destroyable, proving the
     * token is fully operational and not merely loggable-into. */
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, aes);
        CHECK_CKR(ret, "C_DestroyObject on the bystander key");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Two logout and login cycles release and reload the signing key. */
static CK_RV test_logout_login_cycle(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-cycle";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_ULONG remaining = 0, prevRemaining = 0;
    int cycle;

    printf("  logout/login cycle keeps the key usable...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &prevRemaining);

    for (cycle = 0; ret == CKR_OK && cycle < 2; cycle++) {
        if (ret == CKR_OK) {
            ret = funcList->C_Logout(session);
            CHECK_CKR(ret, "C_Logout");
        }
        if (ret == CKR_OK) {
            ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
            CHECK_CKR(ret, "C_Login after logout");
        }
        if (ret == CKR_OK) {
            ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1,
                &priv);
            CHECK_CKR(ret, "private key after re-login");
        }
        if (ret == CKR_OK) {
            ret = hss_sign(session, priv, &sig, &sigLen);
            CHECK_CKR(ret, "sign after re-login");
        }
        if (ret == CKR_OK) {
            ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1,
                &pub);
        }
        if (ret == CKR_OK)
            ret = hss_verify(session, pub, sig, sigLen);
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
        /* The index must move forward across the cycle, never back. */
        if (ret == CKR_OK) {
            ret = get_keys_remaining(session, priv, &remaining);
            CHECK_CKR(ret, "keys-remaining after cycle");
        }
        if (ret == CKR_OK && remaining >= prevRemaining) {
            fprintf(stderr,
                "\nkeys-remaining did not advance across cycle %d "
                "(%lu -> %lu) - FAIL\n", cycle,
                (unsigned long)prevRemaining, (unsigned long)remaining);
            ret = CKR_GENERAL_ERROR;
        }
        prevRemaining = remaining;
    }
    if (ret == CKR_OK)
        printf("    two logout/login cycles, state advanced each time\n");
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Sign with the key under id and verify the signature. */
static CK_RV sign_verify_by_id(CK_SESSION_HANDLE session, CK_BYTE* id,
    CK_ULONG idLen)
{
    CK_RV ret;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;

    ret = find_by_id(session, CKO_PRIVATE_KEY, id, idLen, &priv);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, idLen, &pub);
    if (ret == CKR_OK)
        ret = hss_sign(session, priv, &sig, &sigLen);
    if (ret == CKR_OK)
        ret = hss_verify(session, pub, sig, sigLen);
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* C_SetPIN re-seals the state of loaded and unloaded keys. */
static CK_RV test_set_pin_reseals_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE idA[] = "hss-pin-a";
    CK_BYTE idB[] = "hss-pin-b";
    CK_UTF8CHAR newPin[] = "hss-new-user-pin";
    CK_ULONG newPinLen = sizeof(newPin) - 1;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    printf("  C_SetPIN keeps HSS keys usable...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idA, sizeof(idA) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen A");
    }
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen B");
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idA, sizeof(idA) - 1);
        CHECK_CKR(ret, "sign A before PIN change");
    }
    /* Keys loaded: change the PIN while logged in. */
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            newPinLen);
        CHECK_CKR(ret, "C_SetPIN while logged in");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();

    if (ret == CKR_OK)
        ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_USER, newPin, newPinLen);
        CHECK_CKR(ret, "login with new PIN");
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idA, sizeof(idA) - 1);
        CHECK_CKR(ret, "sign A after PIN change");
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idB, sizeof(idB) - 1);
        CHECK_CKR(ret, "sign B after PIN change");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();

    /* Keys never loaded: change the PIN back without logging in. */
    if (ret == CKR_OK)
        ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, newPin, newPinLen, userPin,
            userPinLen);
        CHECK_CKR(ret, "C_SetPIN without login");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "login with original PIN");
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idA, sizeof(idA) - 1);
        CHECK_CKR(ret, "sign A after second PIN change");
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idB, sizeof(idB) - 1);
        CHECK_CKR(ret, "sign B after second PIN change");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Load and C_Login both decode the key on an empty-PIN token. */
static CK_RV test_empty_pin_redecode(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-empty-pin";
    byte* savedPin = userPin;
    int savedPinLen = userPinLen;
    CK_TOKEN_INFO info;

    printf("  empty-PIN token decodes the key at load and login...\n");
    ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = funcList->C_GetTokenInfo(slot, &info);
    pkcs11_final();
    if (ret != CKR_OK)
        return ret;
    if (info.ulMinPinLen > 0) {
        printf("    skipped: empty PIN not allowed\n");
        return CKR_OK;
    }
    userPin = (byte*)"";
    userPinLen = 0;
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();

    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign after reload");
    }
    close_session(session);
    pkcs11_final();
    userPin = savedPin;
    userPinLen = savedPinLen;
    return ret;
}

/* C_Sign reports the length it needs, and keygen needs a login. */
static CK_RV test_sign_api_contract(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-api";
    CK_MECHANISM mech = { CKM_HSS, NULL, 0 };
    CK_MECHANISM genMech = { CKM_HSS_KEY_PAIR_GEN, NULL, 0 };
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0, shortLen = 0;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_PRIVATE,        &ckFalse,      sizeof(ckFalse)      },
        { CKA_HSS_LEVELS,     &hssLevels,    sizeof(hssLevels)    },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &ckTrue,  sizeof(ckTrue)  },
        { CKA_PRIVATE, &ckFalse, sizeof(ckFalse) },
        { CKA_SIGN,    &ckTrue,  sizeof(ckTrue)  },
    };

    printf("  C_Sign length and keygen login checks...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = funcList->C_SignInit(session, &mech, priv);
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, NULL,
            &sigLen);
    }
    if (ret == CKR_OK) {
        sig = (CK_BYTE*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL)
            ret = CKR_HOST_MEMORY;
    }
    if (ret == CKR_OK) {
        shortLen = sigLen - 1;
        sret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &shortLen);
        CHECK_CKR_FAIL(sret, CKR_BUFFER_TOO_SMALL, "C_Sign short buffer");
        if (sret != CKR_BUFFER_TOO_SMALL || shortLen != sigLen) {
            fprintf(stderr, "\nshort buffer reported %lu, need %lu - FAIL\n",
                (unsigned long)shortLen, (unsigned long)sigLen);
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &sigLen);
        CHECK_CKR(ret, "C_Sign after the short buffer");
    }
    /* The length is refused before a leaf is used, so the key signs on. */
    if (ret == CKR_OK)
        ret = funcList->C_SignInit(session, &mech, priv);
    if (ret == CKR_OK) {
        sret = funcList->C_Sign(session, (CK_BYTE*)testMsg, 0x80000000UL, sig,
            &sigLen);
        CHECK_CKR_FAIL(sret, CKR_DATA_LEN_RANGE, "C_Sign with a 2 GiB length");
        if (sret != CKR_DATA_LEN_RANGE)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign after an oversized length");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_Logout(session);
        CHECK_CKR(ret, "C_Logout");
    }
    /* Without a login there is no token key to seal the state with. */
    if (ret == CKR_OK) {
        sret = funcList->C_GenerateKeyPair(session, &genMech, pubTmpl,
            sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
        CHECK_CKR_FAIL(sret, CKR_USER_NOT_LOGGED_IN, "keygen without login");
        if (sret != CKR_USER_NOT_LOGGED_IN)
            ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    funcList->C_CloseSession(session);
    pkcs11_final();
    return ret;
}

/* A second C_SignInit during an HSS sign returns CKR_OPERATION_ACTIVE. */
static CK_RV test_sign_init_operation_active(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-active";
    CK_MECHANISM mech;
    CK_BYTE sig[4096];
    CK_ULONG sigLen;

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    printf("  a second C_SignInit is refused while one is active...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR(ret, "first C_SignInit");
    }
    if (ret == CKR_OK) {
        sret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(sret, CKR_OPERATION_ACTIVE, "second C_SignInit");
        if (sret != CKR_OPERATION_ACTIVE)
            ret = CKR_GENERAL_ERROR;
        else
            printf("    second C_SignInit returned CKR_OPERATION_ACTIVE\n");
    }
    /* The first operation must still be the live one and complete normally. */
    if (ret == CKR_OK) {
        sigLen = sizeof(sig);
        ret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &sigLen);
        CHECK_CKR(ret, "C_Sign completes the original operation");
    }
    if (ret == CKR_OK)
        ret = hss_verify(session, pub, sig, sigLen);
    close_session(session);
    pkcs11_final();
    return ret;
}


#ifndef _WIN32
/* C_SetPIN leaves a damaged key record alone and re-seals the others. */
static CK_RV test_set_pin_damaged_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE idA[] = "hss-damaged";
    CK_BYTE idB[] = "hss-intact";
    CK_UTF8CHAR newPin[] = "hss-new-user-pin";
    CK_ULONG newPinLen = sizeof(newPin) - 1;
    char recPath[512];
    FILE* f;
    CK_BYTE b = 0;

    printf("  C_SetPIN with a damaged key record...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idA, sizeof(idA) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen A");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen B");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    /* Flip the last tag byte of A's sealed state. */
    if (ret == CKR_OK) {
        f = fopen(recPath, "rb+");
        if (f == NULL || fseek(f, -1, SEEK_END) != 0 ||
                fread(&b, 1, 1, f) != 1) {
            ret = CKR_GENERAL_ERROR;
        }
        else {
            b ^= 0xFF;
            if (fseek(f, -1, SEEK_END) != 0 || fwrite(&b, 1, 1, f) != 1)
                ret = CKR_GENERAL_ERROR;
        }
        if (f != NULL)
            fclose(f);
    }
    if (ret == CKR_OK)
        ret = reopen_token_quiet(&session);
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            newPinLen);
        CHECK_CKR(ret, "C_SetPIN with a damaged key record");
    }
    if (ret == CKR_OK)
        ret = funcList->C_Logout(session);
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_USER, newPin, newPinLen);
        CHECK_CKR(ret, "login with new PIN");
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idB, sizeof(idB) - 1);
        CHECK_CKR(ret, "sign B after PIN change");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

#ifdef DEBUG_WOLFPKCS11
#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Session_SetAddObjectHook(void (*hook)(void));
#ifdef __cplusplus
}
#endif

static CK_SESSION_HANDLE raceSession = CK_INVALID_HANDLE;
static CK_UTF8CHAR racePin[] = "hss-race-user-pin";
static CK_RV raceRet = CKR_OK;
static int raceFired = 0;

/* Change the PIN between sealing the genesis state and adding the key. */
static void race_set_pin_hook(void)
{
    if (!raceFired) {
        raceFired = 1;
        raceRet = funcList->C_SetPIN(raceSession, userPin, userPinLen,
            racePin, sizeof(racePin) - 1);
    }
}

/* A keygen that a C_SetPIN overtakes seals the key under the new token key. */
static CK_RV test_keygen_set_pin_race(void)
{
    CK_RV ret, gret = CKR_OK;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-race";
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    printf("  keygen overtaken by C_SetPIN...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &raceSession);
    if (ret == CKR_OK) {
        raceFired = 0;
        raceRet = CKR_OK;
        WP11_Session_SetAddObjectHook(race_set_pin_hook);
        gret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        WP11_Session_SetAddObjectHook(NULL);
        CHECK_CKR(raceRet, "C_SetPIN during keygen");
        CHECK_CKR(gret, "keygen overtaken by C_SetPIN");
        ret = (raceRet != CKR_OK) ? raceRet : gret;
    }
    if (raceSession != CK_INVALID_HANDLE)
        funcList->C_CloseSession(raceSession);
    raceSession = CK_INVALID_HANDLE;
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK) {
        ret = pkcs11_init();
        if (ret == CKR_OK)
            ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
        if (ret == CKR_OK) {
            ret = funcList->C_Login(session, CKU_USER, racePin,
                sizeof(racePin) - 1);
        }
        if (ret == CKR_OK) {
            ret = sign_verify_by_id(session, id, sizeof(id) - 1);
            CHECK_CKR(ret, "sign the raced key after reload");
        }
        close_session(session);
        pkcs11_final();
    }
    return ret;
}
#endif /* DEBUG_WOLFPKCS11 */

/* C_InitToken removes the records of the keys it discards. */
static CK_RV test_init_token_removes_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-reinit";
    int cnt;

    printf("  C_InitToken removes the old key records...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    close_session(session);
    if (ret == CKR_OK && count_store_files("wp11_hsskey_priv_") != 1)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK)
        ret = pkcs11_init_token();
    if (ret == CKR_OK) {
        cnt = count_store_files("wp11_hsskey_");
        if (cnt != 0) {
            fprintf(stderr, "\n%d key record(s) left after C_InitToken - "
                "FAIL\n", cnt);
            ret = CKR_GENERAL_ERROR;
        }
    }
    pkcs11_final();
    return ret;
}

/* A sign removes an older copy of the key record that an unfinished store
 * pass staged, so finishing that pass cannot roll the state back. */
static CK_RV test_sign_drops_staged_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-staged";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0, signedLeft = 0, reloadLeft = 0;
    char recPath[512];
    char stagedPath[520];
    char markerPath[512];
    const char* base;
    unsigned char buf[4096];
    size_t n;
    FILE* in = NULL;
    FILE* out = NULL;

    printf("  sign drops a stale staged key record...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK) {
        snprintf(stagedPath, sizeof(stagedPath), "%s.new", recPath);
        in = fopen(recPath, "rb");
        out = fopen(stagedPath, "wb");
        if (in == NULL || out == NULL)
            ret = CKR_GENERAL_ERROR;
        while (ret == CKR_OK && (n = fread(buf, 1, sizeof(buf), in)) > 0) {
            if (fwrite(buf, 1, n, out) != n)
                ret = CKR_GENERAL_ERROR;
        }
        if (in != NULL)
            fclose(in);
        if (out != NULL)
            fclose(out);
    }
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "sign");
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &signedLeft);
    if (ret == CKR_OK && (in = fopen(stagedPath, "rb")) != NULL) {
        fclose(in);
        fprintf(stderr, "\nstaged key record survived a sign - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    /* A commit marker naming the record is finished at the next load. */
    if (ret == CKR_OK) {
        base = strrchr(recPath, '/');
        snprintf(markerPath, sizeof(markerPath), "%s/wp11_txn_%016lx_commit",
            storeDir, (unsigned long)slot);
        out = fopen(markerPath, "wb");
        if (out == NULL || base == NULL ||
                fprintf(out, "%s\n", base + 1) < 0) {
            ret = CKR_GENERAL_ERROR;
        }
        if (out != NULL)
            fclose(out);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &reloadLeft);
    if (ret == CKR_OK && reloadLeft != signedLeft) {
        fprintf(stderr, "\nstate rolled back on reload: %lu -> %lu - FAIL\n",
            (unsigned long)signedLeft, (unsigned long)reloadLeft);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* C_CopyObject refuses an HSS private key, which reports CKA_COPYABLE FALSE. */
static CK_RV test_copy_refused(void)
{
    CK_RV ret, cret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-copy";
    CK_BBOOL copyable = CK_TRUE;
    CK_ATTRIBUTE a = { CKA_COPYABLE, NULL, sizeof(CK_BBOOL) };

    printf("  C_CopyObject refuses an HSS private key...\n");
    a.pValue = &copyable;
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, &a, 1);
        CHECK_CKR(ret, "get CKA_COPYABLE");
    }
    if (ret == CKR_OK && copyable != CK_FALSE) {
        fprintf(stderr, "\nHSS private key reports CKA_COPYABLE TRUE - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        cret = funcList->C_CopyObject(session, priv, NULL, 0, &copy);
        CHECK_CKR_FAIL(cret, CKR_ACTION_PROHIBITED, "C_CopyObject");
        if (cret != CKR_ACTION_PROHIBITED)
            ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

static CK_RV read_file(const char* path, CK_BYTE* buf, size_t bufSz,
    size_t* len)
{
    FILE* f = fopen(path, "rb");

    if (f == NULL)
        return CKR_GENERAL_ERROR;
    *len = fread(buf, 1, bufSz, f);
    fclose(f);
    return (*len > 0 && *len < bufSz) ? CKR_OK : CKR_GENERAL_ERROR;
}

static CK_RV write_file(const char* path, const CK_BYTE* buf, size_t len)
{
    CK_RV ret = CKR_OK;
    FILE* f = fopen(path, "wb");

    if (f == NULL || fwrite(buf, 1, len, f) != len)
        ret = CKR_GENERAL_ERROR;
    if (f != NULL)
        fclose(f);
    return ret;
}

/* Sign with the key under id, expecting the given result. */
static CK_RV sign_expect(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
    CK_RV expected, const char* msg)
{
    CK_RV sret;
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;

    sret = hss_sign(session, priv, &sig, &sigLen);
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    CHECK_CKR_FAIL(sret, expected, msg);
    return (sret == expected) ? CKR_OK : CKR_GENERAL_ERROR;
}

/* A stored state moved back while the key is loaded is refused. */
static CK_RV test_rollback_refused(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-rollback";
    char recPath[512];
    static CK_BYTE saved[4096];
    size_t savedLen = 0;

    printf("  a stored state moved back is refused...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK)
        ret = read_file(recPath, saved, sizeof(saved), &savedLen);
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign");
    if (ret == CKR_OK)
        ret = write_file(recPath, saved, savedLen);
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR, "sign after rollback");
    /* Reloading a disabled key does not take the older state either. */
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR,
            "second sign after rollback");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Another key's record at the key's store id is refused, not overwritten. */
static CK_RV test_moved_record_refused(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, privA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privB = CK_INVALID_HANDLE;
    CK_BYTE idA[] = "hss-moved-a";
    CK_BYTE idB[] = "hss-moved-b";
    char pathA[512];
    char pathB[512];
    static CK_BYTE recB[4096];
    size_t lenB = 0;
    DIR* d;
    struct dirent* e;
    const char* prefix = "wp11_hsskey_priv_";

    printf("  another key's record at the key's id is refused...\n");
    pathA[0] = pathB[0] = '\0';
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idA, sizeof(idA) - 1, &pub, &privA);
        CHECK_CKR(ret, "keygen A");
    }
    if (ret == CKR_OK)
        ret = find_key_record(pathA, sizeof(pathA));
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pub, &privB);
        CHECK_CKR(ret, "keygen B");
    }
    if (ret == CKR_OK && (d = opendir(storeDir)) != NULL) {
        while ((e = readdir(d)) != NULL) {
            if (strncmp(e->d_name, prefix, strlen(prefix)) == 0 &&
                    strcmp(strrchr(pathA, '/') + 1, e->d_name) != 0) {
                snprintf(pathB, sizeof(pathB), "%s/%s", storeDir, e->d_name);
            }
        }
        closedir(d);
    }
    if (ret == CKR_OK && pathB[0] == '\0')
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK)
        ret = read_file(pathB, recB, sizeof(recB), &lenB);
    if (ret == CKR_OK)
        ret = write_file(pathA, recB, lenB);
    if (ret == CKR_OK)
        ret = sign_expect(session, privA, CKR_DEVICE_ERROR, "sign A");
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Sign count times with the key under id and write each leaf index to fd. */
static CK_RV sign_leaves(CK_BYTE* id, CK_ULONG idLen, int count, int fd,
    unsigned long* leaves)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    unsigned long q;
    int i;

    ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, idLen, &priv);
    for (i = 0; ret == CKR_OK && i < count; i++) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        if (ret == CKR_OK) {
            q = sig_leaf(sig);
            if (fd >= 0 && write(fd, &q, sizeof(q)) != (ssize_t)sizeof(q))
                ret = CKR_GENERAL_ERROR;
            if (leaves != NULL)
                leaves[i] = q;
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Two processes signing with one key never share a leaf. */
static CK_RV test_two_process_signing(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-two-proc";
    enum { PER_PROC = 12 };
    unsigned long leaves[2 * PER_PROC];
    CK_ULONG left = 0;
    int fds[2];
    pid_t pid;
    int status = 0;
    int i, j;

    printf("  two processes signing with one key...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    close_session(session);
    pkcs11_final();
    if (ret != CKR_OK)
        return ret;
    if (pipe(fds) != 0)
        return CKR_GENERAL_ERROR;

    pid = fork();
    if (pid == 0) {
        close(fds[0]);
        _exit(sign_leaves(id, sizeof(id) - 1, PER_PROC, fds[1], NULL) ==
            CKR_OK ? 0 : 1);
    }
    close(fds[1]);
    if (pid < 0) {
        close(fds[0]);
        return CKR_GENERAL_ERROR;
    }
    ret = sign_leaves(id, sizeof(id) - 1, PER_PROC, -1, leaves);
    for (i = 0; i < PER_PROC; i++) {
        if (read(fds[0], &leaves[PER_PROC + i], sizeof(leaves[0])) !=
                (ssize_t)sizeof(leaves[0])) {
            ret = CKR_GENERAL_ERROR;
            break;
        }
    }
    close(fds[0]);
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
        fprintf(stderr, "\nchild signer failed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    for (i = 0; ret == CKR_OK && i < 2 * PER_PROC; i++) {
        for (j = i + 1; j < 2 * PER_PROC; j++) {
            if (leaves[i] == leaves[j]) {
                fprintf(stderr, "\nleaf %lu used twice - FAIL\n", leaves[i]);
                ret = CKR_GENERAL_ERROR;
                break;
            }
        }
    }
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &left);
    if (ret == CKR_OK && left != HSS_H5_SIGS - 2 * PER_PROC) {
        fprintf(stderr, "\n%lu left after %d signatures - FAIL\n",
            (unsigned long)left, 2 * PER_PROC);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A loaded key picks up a state that a forked child advanced. */
static CK_RV test_refresh_from_store(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-refresh";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    unsigned long childLeaf = 0, parentLeaf;
    int fds[2];
    pid_t pid;
    int status = 0;

    printf("  a loaded key picks up a state another process advanced...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret != CKR_OK || pipe(fds) != 0) {
        close_session(session);
        pkcs11_final();
        return (ret != CKR_OK) ? ret : CKR_GENERAL_ERROR;
    }

    pid = fork();
    if (pid == 0) {
        /* A forked child must start the library again before using it. */
        close(fds[0]);
        funcList->C_Finalize(NULL);
        _exit(sign_leaves(id, sizeof(id) - 1, 1, fds[1], NULL) == CKR_OK ?
            0 : 1);
    }
    close(fds[1]);
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0 ||
            read(fds[0], &childLeaf, sizeof(childLeaf)) !=
                (ssize_t)sizeof(childLeaf)) {
        fprintf(stderr, "\nchild signer failed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    close(fds[0]);
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "sign after the child");
    }
    if (ret == CKR_OK) {
        parentLeaf = sig_leaf(sig);
        if (parentLeaf <= childLeaf) {
            fprintf(stderr, "\nparent signed leaf %lu after child's %lu - "
                "FAIL\n", parentLeaf, childLeaf);
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A store pass in a process holding an older state keeps the newer one that
 * another process stored, also when it re-seals it for a new PIN. */
static CK_RV test_store_pass_keeps_newer_state(void)
{
    CK_RV ret, pret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-newer";
    static CK_UTF8CHAR newPin[] = "hss-new-user-pin";
    byte* oldPin = userPin;
    int oldPinLen = userPinLen;
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_ULONG left = 0;
    unsigned long childLeaf = 0;
    int fds[2];
    pid_t pid;
    int status = 0;

    printf("  a store pass keeps a newer state from another process...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret != CKR_OK || pipe(fds) != 0) {
        close_session(session);
        pkcs11_final();
        return (ret != CKR_OK) ? ret : CKR_GENERAL_ERROR;
    }
    pid = fork();
    if (pid == 0) {
        close(fds[0]);
        funcList->C_Finalize(NULL);
        _exit(sign_leaves(id, sizeof(id) - 1, 1, fds[1], NULL) == CKR_OK ?
            0 : 1);
    }
    close(fds[1]);
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0 ||
            read(fds[0], &childLeaf, sizeof(childLeaf)) !=
                (ssize_t)sizeof(childLeaf)) {
        fprintf(stderr, "\nchild signer failed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    close(fds[0]);
    /* A PIN change stores every object, this key included. */
    if (ret == CKR_OK) {
        pret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            sizeof(newPin) - 1);
        CHECK_CKR(pret, "C_SetPIN after the child signed");
        ret = pret;
    }
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "sign after the PIN change");
    }
    if (ret == CKR_OK && sig_leaf(sig) == childLeaf) {
        fprintf(stderr, "\nleaf %lu used twice - FAIL\n", childLeaf);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    userPin = newPin;
    userPinLen = (int)sizeof(newPin) - 1;
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &left);
    if (ret == CKR_OK && left != HSS_H5_SIGS - 2) {
        fprintf(stderr, "\n%lu left after two signatures - FAIL\n",
            (unsigned long)left);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    userPin = oldPin;
    userPinLen = oldPinLen;
    return ret;
}

/* The state is sealed to the policy in the object record: a policy change
 * re-seals it, and an object record put back to the old policy is refused. */
static CK_RV test_policy_bound_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-policy";
    CK_ATTRIBUTE a = { CKA_DERIVE, NULL, sizeof(CK_BBOOL) };
    char recPath[512];
    char objPath[520];
    static CK_BYTE objRec[4096];
    size_t objLen = 0;
    const char* suffix;

    printf("  the state is sealed to the object policy...\n");
    a.pValue = &ckTrue;
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK) {
        suffix = strrchr(recPath, '/') + 1 + strlen("wp11_hsskey_priv_");
        snprintf(objPath, sizeof(objPath), "%s/wp11_obj_%s", storeDir, suffix);
        ret = read_file(objPath, objRec, sizeof(objRec), &objLen);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, priv, &a, 1);
        CHECK_CKR(ret, "change CKA_DERIVE");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign after the policy change");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = write_file(objPath, objRec, objLen);
    if (ret == CKR_OK)
        ret = reopen_token_quiet(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR,
            "sign with the old policy in the object record");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A C_SetPIN does not bind a key's record to object attributes that no longer
 * match the digest the record was sealed to. */
static CK_RV test_set_pin_keeps_policy_binding(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-policy-pin";
    CK_ATTRIBUTE a = { CKA_DERIVE, NULL, sizeof(CK_BBOOL) };
    CK_UTF8CHAR newPin[] = "hss-new-user-pin";
    CK_ULONG newPinLen = sizeof(newPin) - 1;
    char recPath[512];
    char objPath[520];
    static CK_BYTE objRec[4096];
    size_t objLen = 0;
    const char* suffix;

    printf("  a PIN change keeps the record's policy binding...\n");
    a.pValue = &ckTrue;
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK) {
        suffix = strrchr(recPath, '/') + 1 + strlen("wp11_hsskey_priv_");
        snprintf(objPath, sizeof(objPath), "%s/wp11_obj_%s", storeDir, suffix);
        ret = read_file(objPath, objRec, sizeof(objRec), &objLen);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, priv, &a, 1);
        CHECK_CKR(ret, "change CKA_DERIVE");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    /* The object record goes back to the policy before the change. */
    if (ret == CKR_OK)
        ret = write_file(objPath, objRec, objLen);
    if (ret == CKR_OK)
        ret = reopen_token_quiet(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR,
            "sign with the old policy in the object record");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            newPinLen);
        CHECK_CKR(ret, "C_SetPIN");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, newPin, newPinLen, userPin,
            userPinLen);
        CHECK_CKR(ret, "C_SetPIN back");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token_quiet(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR,
            "sign after the PIN changes");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Find a key record other than the one at exclude. */
static CK_RV find_other_key_record(const char* exclude, char* path,
    size_t pathLen)
{
    DIR* d;
    struct dirent* e;
    CK_RV ret = CKR_OBJECT_HANDLE_INVALID;
    const char* prefix = "wp11_hsskey_priv_";

    d = opendir(storeDir);
    if (d == NULL)
        return CKR_GENERAL_ERROR;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, strlen(prefix)) == 0) {
            snprintf(path, pathLen, "%s/%s", storeDir, e->d_name);
            if (strcmp(path, exclude) != 0) {
                ret = CKR_OK;
                break;
            }
        }
    }
    closedir(d);
    return ret;
}

/* Moving a key to a freed id takes the newer state another process stored at
 * its old id. */
static CK_RV test_move_keeps_newer_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE oldPub = CK_INVALID_HANDLE, oldPriv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-move";
    static CK_BYTE oldId[] = "hss-move-old";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_ULONG left = 0;
    unsigned long childLeaf = 0;
    int fds[2];
    pid_t pid;
    int status = 0;

    printf("  a moved key keeps the newer state of another process...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            oldId, sizeof(oldId) - 1, &oldPub, &oldPriv);
        CHECK_CKR(ret, "keygen of the older key");
    }
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret != CKR_OK || pipe(fds) != 0) {
        close_session(session);
        pkcs11_final();
        return (ret != CKR_OK) ? ret : CKR_GENERAL_ERROR;
    }
    pid = fork();
    if (pid == 0) {
        close(fds[0]);
        funcList->C_Finalize(NULL);
        _exit(sign_leaves(id, sizeof(id) - 1, 1, fds[1], NULL) == CKR_OK ?
            0 : 1);
    }
    close(fds[1]);
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0 ||
            read(fds[0], &childLeaf, sizeof(childLeaf)) !=
                (ssize_t)sizeof(childLeaf)) {
        fprintf(stderr, "\nchild signer failed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    close(fds[0]);
    /* The newest object moves into the id of the destroyed one. */
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, oldPriv);
        CHECK_CKR(ret, "destroy the older key");
    }
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "sign after the move");
    }
    if (ret == CKR_OK && sig_leaf(sig) == childLeaf) {
        fprintf(stderr, "\nleaf %lu used twice - FAIL\n", childLeaf);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &left);
    if (ret == CKR_OK && left != HSS_H5_SIGS - 2) {
        fprintf(stderr, "\n%lu left after two signatures - FAIL\n",
            (unsigned long)left);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A key without a record that moves into a destroyed key's id does not take
 * that key's state. */
static CK_RV test_moved_damaged_key(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-damaged";
    static CK_BYTE oldId[] = "hss-damaged-old";
    char oldPath[512];
    char recPath[512];

    printf("  a damaged key moved into a destroyed key's id...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            oldId, sizeof(oldId) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen of the older key");
    }
    if (ret == CKR_OK)
        ret = find_key_record(oldPath, sizeof(oldPath));
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_other_key_record(oldPath, recPath, sizeof(recPath));
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK && remove(recPath) != 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, oldId, sizeof(oldId) - 1,
            &priv);
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, priv);
        CHECK_CKR(ret, "destroy the older key");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR,
            "sign with the destroyed key's state");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A process holding a key across another process's policy change does not
 * overwrite the re-sealed record with its old policy. */
static CK_RV test_policy_change_other_process(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-policy-proc";
    CK_ATTRIBUTE a = { CKA_DERIVE, NULL, sizeof(CK_BBOOL) };
    CK_BBOOL derive = CK_FALSE;
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    int toA[2], fromA[2];
    pid_t pidA, pidB;
    int status = 0;
    char c = 0;

    printf("  a policy change in another process is not overwritten...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret != CKR_OK || pipe(toA) != 0 || pipe(fromA) != 0)
        return (ret != CKR_OK) ? ret : CKR_GENERAL_ERROR;

    /* A loads the key, signs after B's change and stops without a store. */
    pidA = fork();
    if (pidA == 0) {
        close(toA[1]);
        close(fromA[0]);
        if (reopen_token(&session) != CKR_OK ||
                find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1,
                    &priv) != CKR_OK ||
                write(fromA[1], &c, 1) != 1 || read(toA[0], &c, 1) != 1) {
            _exit(1);
        }
        (void)hss_sign(session, priv, &sig, &sigLen);
        _exit(0);
    }
    close(toA[0]);
    close(fromA[1]);
    if (pidA < 0 || read(fromA[0], &c, 1) != 1)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        pidB = fork();
        if (pidB == 0) {
            a.pValue = &ckTrue;
            if (reopen_token(&session) != CKR_OK ||
                    find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1,
                        &priv) != CKR_OK ||
                    funcList->C_SetAttributeValue(session, priv, &a, 1) !=
                        CKR_OK) {
                _exit(1);
            }
            close_session(session);
            pkcs11_final();
            _exit(0);
        }
        if (pidB < 0 || waitpid(pidB, &status, 0) < 0 ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "\npolicy change failed - FAIL\n");
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (write(toA[1], &c, 1) != 1)
        ret = CKR_GENERAL_ERROR;
    close(toA[1]);
    close(fromA[0]);
    if (pidA > 0 && (waitpid(pidA, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)) {
        fprintf(stderr, "\nstale signer failed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign with the new policy");
    }
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK) {
        a.pValue = &derive;
        ret = funcList->C_GetAttributeValue(session, priv, &a, 1);
    }
    if (ret == CKR_OK && derive != CK_TRUE) {
        fprintf(stderr, "\npolicy change lost - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A process that loaded the token before another one destroyed a key and
 * signed does not roll the state back when it finalizes. */
static CK_RV test_stale_finalize_keeps_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE oldPub = CK_INVALID_HANDLE, oldPriv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-stale";
    static CK_BYTE oldId[] = "hss-stale-old";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_ULONG left = 0;
    unsigned long last = 0;
    int toB[2], fromB[2];
    pid_t pid;
    int status = 0;
    char c = 0;
    int i;

    printf("  a stale process does not roll the state back...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            oldId, sizeof(oldId) - 1, &oldPub, &oldPriv);
        CHECK_CKR(ret, "keygen of the older key");
    }
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret != CKR_OK || pipe(toB) != 0 || pipe(fromB) != 0)
        return (ret != CKR_OK) ? ret : CKR_GENERAL_ERROR;

    /* B loads the token and finalizes after A's changes. */
    pid = fork();
    if (pid == 0) {
        close(toB[1]);
        close(fromB[0]);
        if (reopen_token(&session) != CKR_OK ||
                write(fromB[1], &c, 1) != 1 || read(toB[0], &c, 1) != 1) {
            _exit(1);
        }
        close_session(session);
        pkcs11_final();
        _exit(0);
    }
    close(toB[0]);
    close(fromB[1]);
    if (pid < 0 || read(fromB[0], &c, 1) != 1)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_PRIVATE_KEY, oldId, sizeof(oldId) - 1,
            &oldPriv);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, oldPriv);
        CHECK_CKR(ret, "destroy the older key");
    }
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    for (i = 0; ret == CKR_OK && i < 2; i++) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        if (ret == CKR_OK) {
            last = sig_leaf(sig);
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (write(toB[1], &c, 1) != 1)
        ret = CKR_GENERAL_ERROR;
    close(toB[1]);
    close(fromB[0]);
    if (pid > 0 && (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)) {
        fprintf(stderr, "\nstale process failed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK && find_by_id_quiet(session, CKO_PRIVATE_KEY, oldId,
            sizeof(oldId) - 1, &oldPriv) == CKR_OK) {
        fprintf(stderr, "\ndestroyed key is back - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &left);
    if (ret == CKR_OK && left != HSS_H5_SIGS - 2) {
        fprintf(stderr, "\n%lu left after two signatures - FAIL\n",
            (unsigned long)left);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = hss_sign(session, priv, &sig, &sigLen);
    if (ret == CKR_OK && sig_leaf(sig) <= last) {
        fprintf(stderr, "\nleaf %lu after %lu - FAIL\n", sig_leaf(sig), last);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A process still using the id a moved key left signs nothing from the old
 * record, also when removing that record fails. */
static CK_RV test_moved_key_old_record(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE oldPub = CK_INVALID_HANDLE, oldPriv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-old-id";
    static CK_BYTE oldId[] = "hss-old-id-gone";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_RV childRv = CKR_OK;
    int toB[2], fromB[2];
    pid_t pid;
    int status = 0;
    char c = 0;
    char objPath[512] = "";
    char inner[600];
    DIR* d;
    struct dirent* e;
    size_t n;
    int blocked = 0;

    printf("  a moved key's old record cannot be signed from...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            oldId, sizeof(oldId) - 1, &oldPub, &oldPriv);
        CHECK_CKR(ret, "keygen of the older key");
    }
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret != CKR_OK || pipe(toB) != 0 || pipe(fromB) != 0)
        return (ret != CKR_OK) ? ret : CKR_GENERAL_ERROR;

    /* B knows the newest key by its id before the move. */
    pid = fork();
    if (pid == 0) {
        close(toB[1]);
        close(fromB[0]);
        if (reopen_token(&session) != CKR_OK ||
                find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1,
                    &priv) != CKR_OK ||
                write(fromB[1], &c, 1) != 1 || read(toB[0], &c, 1) != 1) {
            _exit(1);
        }
        childRv = hss_sign(session, priv, &sig, &sigLen);
        if (write(fromB[1], &childRv, sizeof(childRv)) !=
                (ssize_t)sizeof(childRv)) {
            _exit(2);
        }
        _exit(0);
    }
    close(toB[0]);
    close(fromB[1]);
    if (pid < 0 || read(fromB[0], &c, 1) != 1)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    /* Keep the object record at the newest key's id (3) from being removed,
     * so the old records outlive the destroy. */
    d = opendir(storeDir);
    while (d != NULL && (e = readdir(d)) != NULL) {
        n = strlen(e->d_name);
        if (strncmp(e->d_name, "wp11_obj_", 9) == 0 && n > 17 &&
                strcmp(e->d_name + n - 17, "_0000000000000003") == 0) {
            snprintf(objPath, sizeof(objPath), "%s/%s", storeDir,
                e->d_name);
        }
    }
    if (d != NULL)
        closedir(d);
    snprintf(inner, sizeof(inner), "%s/keep", objPath);
    if (ret == CKR_OK && objPath[0] != '\0' && remove(objPath) == 0 &&
            mkdir(objPath, 0700) == 0) {
        blocked = 1;
        if (write_file(inner, (const CK_BYTE*)"x", 1) != CKR_OK)
            ret = CKR_GENERAL_ERROR;
    }
    else if (ret == CKR_OK) {
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_PRIVATE_KEY, oldId, sizeof(oldId) - 1,
            &oldPriv);
    }
    if (ret == CKR_OK)
        (void)funcList->C_DestroyObject(session, oldPriv);
    if (write(toB[1], &c, 1) != 1 ||
            read(fromB[0], &childRv, sizeof(childRv)) !=
                (ssize_t)sizeof(childRv)) {
        ret = CKR_GENERAL_ERROR;
    }
    close(toB[1]);
    close(fromB[0]);
    if (pid > 0 && (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)) {
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK && childRv != CKR_DEVICE_ERROR) {
        fprintf(stderr, "\nsign from the old id returned %lx - FAIL\n",
            (unsigned long)childRv);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign at the new id");
    }
    if (blocked) {
        (void)remove(inner);
        (void)rmdir(objPath);
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A policy change after another process signed re-seals the newer state,
 * so the key keeps signing here and after a reload. */
static CK_RV test_policy_change_after_other_sign(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-policy-late";
    CK_ATTRIBUTE a = { CKA_DERIVE, NULL, sizeof(CK_BBOOL) };
    CK_ULONG left = 0;
    pid_t pid;
    int status = 0;

    printf("  a policy change keeps the state another process advanced...\n");
    a.pValue = &ckTrue;
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK) {
        pid = fork();
        if (pid == 0) {
            funcList->C_Finalize(NULL);
            _exit(sign_leaves(id, sizeof(id) - 1, 1, -1, NULL) == CKR_OK ?
                0 : 1);
        }
        if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0) {
            fprintf(stderr, "\nchild signer failed - FAIL\n");
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, priv, &a, 1);
        CHECK_CKR(ret, "change CKA_DERIVE");
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign after the policy change");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign after a reload");
    }
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &left);
    if (ret == CKR_OK && left != HSS_H5_SIGS - 3) {
        fprintf(stderr, "\n%lu left after three signatures - FAIL\n",
            (unsigned long)left);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A store pass that cannot read the key's stored record does not write an
 * older state over it. */
static CK_RV test_store_needs_stored_record(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-unreadable";
    static CK_BYTE label[] = "hss-relabelled";
    CK_ATTRIBUTE a = { CKA_LABEL, label, sizeof(label) - 1 };
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    unsigned long childLeaf = 0;
    char recPath[512];
    int fds[2];
    pid_t pid;
    int status = 0;
    int locked = 0;

    if (geteuid() == 0) {
        printf("  skipping the unreadable record test (running as root)\n");
        return CKR_OK;
    }
    printf("  a store pass needs the stored record...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret != CKR_OK || pipe(fds) != 0) {
        close_session(session);
        pkcs11_final();
        return (ret != CKR_OK) ? ret : CKR_GENERAL_ERROR;
    }
    pid = fork();
    if (pid == 0) {
        close(fds[0]);
        funcList->C_Finalize(NULL);
        _exit(sign_leaves(id, sizeof(id) - 1, 1, fds[1], NULL) == CKR_OK ?
            0 : 1);
    }
    close(fds[1]);
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0 ||
            read(fds[0], &childLeaf, sizeof(childLeaf)) !=
                (ssize_t)sizeof(childLeaf)) {
        fprintf(stderr, "\nchild signer failed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    close(fds[0]);
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK) {
        if (chmod(recPath, 0) != 0)
            ret = CKR_GENERAL_ERROR;
        else
            locked = 1;
    }
    /* The attribute change stands; its store pass fails and is redone. */
    if (ret == CKR_OK)
        (void)funcList->C_SetAttributeValue(session, priv, &a, 1);
    if (locked)
        (void)chmod(recPath, 0600);
    if (ret == CKR_OK)
        ret = hss_sign(session, priv, &sig, &sigLen);
    if (ret == CKR_OK && sig_leaf(sig) == childLeaf) {
        fprintf(stderr, "\nleaf %lu used twice - FAIL\n", childLeaf);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* C_VerifyInit refuses an HSS private key, C_SignInit a public key, and
 * C_SignUpdate refuses the single-part mechanism without using a leaf. */
static CK_RV test_key_class_and_single_part(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-key-class";
    CK_ATTRIBUTE verify = { CKA_VERIFY, &ckTrue, sizeof(ckTrue) };
    CK_ATTRIBUTE sign = { CKA_SIGN, &ckTrue, sizeof(ckTrue) };
    CK_MECHANISM mech = { CKM_HSS, NULL, 0 };
    CK_ULONG before = 0, after = 0;

    printf("  key class checks and single-part signing...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, priv, &verify, 1);
        CHECK_CKR(ret, "set CKA_VERIFY on the private key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
            "C_VerifyInit with the private key");
        ret = (ret == CKR_KEY_TYPE_INCONSISTENT) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, pub, &sign, 1);
        CHECK_CKR(ret, "set CKA_SIGN on the public key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, pub);
        CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
            "C_SignInit with the public key");
        ret = (ret == CKR_KEY_TYPE_INCONSISTENT) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &before);
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR(ret, "C_SignInit with the private key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignUpdate(session, (CK_BYTE*)testMsg,
            TEST_MSG_LEN);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID, "C_SignUpdate");
        ret = (ret == CKR_MECHANISM_INVALID) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &after);
    if (ret == CKR_OK && after != before) {
        fprintf(stderr, "\nC_SignUpdate used a leaf - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A key whose record goes missing while it is loaded stops signing, but the
 * token still changes its PIN, signs with other keys and finalizes. */
static CK_RV test_record_lost_while_loaded(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, privA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privB = CK_INVALID_HANDLE;
    CK_BYTE idA[] = "hss-lost";
    CK_BYTE idB[] = "hss-kept";
    CK_UTF8CHAR newPin[] = "hss-new-user-pin";
    CK_ULONG newPinLen = sizeof(newPin) - 1;
    char recPath[512];

    printf("  a key record lost while loaded...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idA, sizeof(idA) - 1, &pub, &privA);
        CHECK_CKR(ret, "keygen A");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pub, &privB);
        CHECK_CKR(ret, "keygen B");
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, privA, CKR_OK, "sign A");
    if (ret == CKR_OK && remove(recPath) != 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            newPinLen);
        CHECK_CKR(ret, "C_SetPIN with a lost key record");
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, privB, CKR_OK, "sign B");
    if (ret == CKR_OK)
        ret = sign_expect(session, privA, CKR_DEVICE_ERROR, "sign A");
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, newPin, newPinLen, userPin,
            userPinLen);
        CHECK_CKR(ret, "C_SetPIN back");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    if (ret == CKR_OK) {
        ret = funcList->C_Finalize(NULL);
        CHECK_CKR(ret, "C_Finalize with a lost key record");
    }
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idB, sizeof(idB) - 1);
        CHECK_CKR(ret, "sign B after reload");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A loaded key whose record goes missing and then moves into a destroyed
 * object's id stops signing, but the token keeps storing. */
static CK_RV test_lost_record_key_moves(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE oldPriv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE oldPub = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-lost-moved";
    static CK_BYTE oldId[] = "hss-lost-moved-old";
    char oldPath[512];
    char recPath[512];

    printf("  a loaded key with a lost record moves...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            oldId, sizeof(oldId) - 1, &oldPub, &oldPriv);
        CHECK_CKR(ret, "keygen of the older key");
    }
    if (ret == CKR_OK)
        ret = find_key_record(oldPath, sizeof(oldPath));
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_other_key_record(oldPath, recPath, sizeof(recPath));
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign before the loss");
    if (ret == CKR_OK && remove(recPath) != 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, oldPriv);
        CHECK_CKR(ret, "destroy the older key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, oldPub);
        CHECK_CKR(ret, "destroy after the move");
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR, "sign moved key");
    close_session(session);
    session = CK_INVALID_HANDLE;
    if (ret == CKR_OK) {
        ret = funcList->C_Finalize(NULL);
        CHECK_CKR(ret, "C_Finalize after the move");
    }
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR,
            "sign moved key after reload");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* An unreadable record fails a C_SetPIN and holds back a policy change's
 * store pass, so the key is not left sealed under a stale key or policy. */
static CK_RV test_unreadable_record_refuses_change(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-unreadable";
    CK_UTF8CHAR newPin[] = "hss-new-user-pin";
    CK_ULONG newPinLen = sizeof(newPin) - 1;
    CK_BBOOL derive = CK_TRUE;
    CK_ATTRIBUTE a = { CKA_DERIVE, &derive, sizeof(derive) };
    char recPath[512];
    FILE* f;

    if (geteuid() == 0) {
        printf("  skipping the unreadable record change test (root)\n");
        return CKR_OK;
    }
    printf("  an unreadable record refuses a PIN or policy change...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign");
    if (ret == CKR_OK && chmod(recPath, 0) != 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK && (f = fopen(recPath, "rb")) != NULL) {
        fclose(f);
        (void)chmod(recPath, 0600);
        printf("  skipping: the record cannot be made unreadable\n");
        close_session(session);
        pkcs11_final();
        return CKR_OK;
    }
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_FUNCTION_FAILED,
            "sign with an unreadable record");
    }
    if (ret == CKR_OK && funcList->C_SetPIN(session, userPin, userPinLen,
            newPin, newPinLen) == CKR_OK) {
        fprintf(stderr, "\nC_SetPIN with an unreadable record - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    /* The policy change stands; its store pass fails and is redone. */
    if (ret == CKR_OK)
        (void)funcList->C_SetAttributeValue(session, priv, &a, 1);
    (void)chmod(recPath, 0600);
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign once readable");
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign after reload");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}


/* A record rolled back behind a newer state this process already took over
 * in a store pass is refused, though it is not behind the last signature. */
static CK_RV test_rollback_after_adopt(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-adopt-rollback";
    static CK_BYTE label[] = "hss-adopt-relabel";
    CK_ATTRIBUTE a = { CKA_LABEL, label, sizeof(label) - 1 };
    static CK_BYTE saved[4096];
    size_t savedLen = 0;
    char recPath[512];
    pid_t pid;
    int status = 0;

    printf("  a rollback behind an adopted state...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign");
    if (ret == CKR_OK)
        ret = read_file(recPath, saved, sizeof(saved), &savedLen);
    if (ret == CKR_OK) {
        pid = fork();
        if (pid == 0) {
            funcList->C_Finalize(NULL);
            _exit(sign_leaves(id, sizeof(id) - 1, 2, -1, NULL) == CKR_OK ?
                0 : 1);
        }
        if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0) {
            fprintf(stderr, "\nchild signer failed - FAIL\n");
            ret = CKR_GENERAL_ERROR;
        }
    }
    /* Storing the key takes over the child's newer record. */
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, priv, &a, 1);
        CHECK_CKR(ret, "relabel");
    }
    if (ret == CKR_OK)
        ret = write_file(recPath, saved, savedLen);
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR,
            "sign from the rolled-back record");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A record that fails to read during a move fails the store pass instead of
 * being taken as damaged, so the key keeps its state. */
static CK_RV test_record_read_error_keeps_key(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE oldPriv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-read-error";
    static CK_BYTE oldId[] = "hss-read-error-old";
    static CK_BYTE saved[4096];
    size_t savedLen = 0;
    char oldPath[512];
    char recPath[512];
    int blocked = 0;

    printf("  a record read error during a move...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            oldId, sizeof(oldId) - 1, &pub, &oldPriv);
        CHECK_CKR(ret, "keygen of the older key");
    }
    if (ret == CKR_OK)
        ret = find_key_record(oldPath, sizeof(oldPath));
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_other_key_record(oldPath, recPath, sizeof(recPath));
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign");
    if (ret == CKR_OK)
        ret = read_file(recPath, saved, sizeof(saved), &savedLen);
    /* A directory at the record's name opens but fails to read. */
    if (ret == CKR_OK) {
        if (remove(recPath) != 0 || mkdir(recPath, 0700) != 0)
            ret = CKR_GENERAL_ERROR;
        else
            blocked = 1;
    }
    if (ret == CKR_OK &&
            funcList->C_DestroyObject(session, oldPriv) == CKR_OK) {
        fprintf(stderr, "\ndestroy with an unreadable record - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    if (blocked) {
        (void)rmdir(recPath);
        if (write_file(recPath, saved, savedLen) != CKR_OK)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign once readable");
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign after reload");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A policy change on a key whose record is lost while it is loaded leaves
 * the rest of the token working. */
static CK_RV test_policy_change_lost_record(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, privA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privB = CK_INVALID_HANDLE;
    CK_BYTE idA[] = "hss-lost-policy";
    CK_BYTE idB[] = "hss-kept-policy";
    CK_BYTE idC[] = "hss-after-policy";
    CK_UTF8CHAR newPin[] = "hss-new-user-pin";
    CK_ULONG newPinLen = sizeof(newPin) - 1;
    CK_ATTRIBUTE a = { CKA_DERIVE, NULL, sizeof(CK_BBOOL) };
    char recPath[512];

    a.pValue = &ckTrue;
    printf("  a policy change on a key whose record was lost...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idA, sizeof(idA) - 1, &pub, &privA);
        CHECK_CKR(ret, "keygen A");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pub, &privB);
        CHECK_CKR(ret, "keygen B");
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, privA, CKR_OK, "sign A");
    if (ret == CKR_OK && remove(recPath) != 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, privA, &a, 1);
        CHECK_CKR(ret, "change CKA_DERIVE on A");
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, privB, CKR_OK, "sign B");
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            newPinLen);
        CHECK_CKR(ret, "C_SetPIN");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, newPin, newPinLen, userPin,
            userPinLen);
        CHECK_CKR(ret, "C_SetPIN back");
    }
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idC, sizeof(idC) - 1, &pub, &privB);
        CHECK_CKR(ret, "keygen C");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idC, sizeof(idC) - 1);
        CHECK_CKR(ret, "sign C after reload");
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idB, sizeof(idB) - 1);
        CHECK_CKR(ret, "sign B after reload");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

static CK_RV check_hss_params(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
    const char* when)
{
    CK_RV ret;
    CK_ULONG levels = 0, lmsType = 0, lmotsType = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_HSS_LEVELS,     &levels,    sizeof(levels)    },
        { CKA_HSS_LMS_TYPE,   &lmsType,   sizeof(lmsType)   },
        { CKA_HSS_LMOTS_TYPE, &lmotsType, sizeof(lmotsType) },
    };

    ret = funcList->C_GetAttributeValue(session, obj, tmpl,
        sizeof(tmpl) / sizeof(*tmpl));
    CHECK_CKR(ret, when);
    if (ret == CKR_OK && (levels != hssLevels || lmsType != hssLmsType ||
            lmotsType != hssLmotsType)) {
        fprintf(stderr, "\n%s: wrong parameters - FAIL\n", when);
        ret = CKR_GENERAL_ERROR;
    }
    return ret;
}

/* A private key that is not loaded reports its parameters from its record. */
static CK_RV test_params_without_login(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_MECHANISM genMech = { CKM_HSS_KEY_PAIR_GEN, NULL, 0 };
    CK_BYTE id[] = "hss-public-params";
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     &hssLevels,    sizeof(hssLevels)    },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &ckTrue,  sizeof(ckTrue)  },
        { CKA_PRIVATE, &ckFalse, sizeof(ckFalse) },
        { CKA_SIGN,    &ckTrue,  sizeof(ckTrue)  },
        { CKA_ID,      id,       sizeof(id) - 1  },
    };

    printf("  parameters of a key that is not loaded...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, &genMech, pubTmpl,
            sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Logout(session);
        CHECK_CKR(ret, "C_Logout");
    }
    if (ret == CKR_OK)
        ret = check_hss_params(session, priv, "parameters after logout");
    funcList->C_CloseSession(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = pkcs11_init();
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
            &session);
    }
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = check_hss_params(session, priv, "parameters before login");
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    pkcs11_final();
    return ret;
}

/* With a key's record gone, an object reported created survives a
 * reload. */
static CK_RV test_create_missing_record(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-missing";
    static CK_BYTE aesId[] = "aes-missing";
    static CK_BYTE label[] = "hss-missing-label";
    CK_ATTRIBUTE a = { CKA_LABEL, label, sizeof(label) - 1 };
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BYTE aesKey[32] = { 0 };
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_ID,       aesId,        sizeof(aesId) - 1   },
        { CKA_VALUE,    aesKey,       sizeof(aesKey)      },
    };
    char recPath[512];

    printf("  a create with a key record missing...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK && remove(recPath) != 0)
        ret = CKR_GENERAL_ERROR;
    /* The failed pass makes the next one store every object. */
    if (ret == CKR_OK)
        (void)funcList->C_SetAttributeValue(session, priv, &a, 1);
    sret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        sret = funcList->C_CreateObject(session, aesTmpl,
            sizeof(aesTmpl) / sizeof(*aesTmpl), &aes);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK && sret == CKR_OK) {
        ret = reopen_token(&session);
        if (ret == CKR_OK) {
            ret = find_by_id(session, CKO_SECRET_KEY, aesId,
                sizeof(aesId) - 1, &aes);
        }
        if (ret != CKR_OK) {
            fprintf(stderr, "\nAES key reported created is gone - FAIL\n");
            ret = CKR_GENERAL_ERROR;
        }
        close_session(session);
        pkcs11_final();
    }
    return ret;
}

/* A policy change on a key whose record does not load is refused, so the
 * token keeps storing and other keys keep signing. */
static CK_RV test_policy_change_unloaded_key(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-unloaded";
    static CK_BYTE otherId[] = "hss-unloaded-other";
    CK_ATTRIBUTE a = { CKA_DERIVE, NULL, sizeof(CK_BBOOL) };
    char otherPath[512];
    char recPath[512];
    static CK_BYTE rec[4096];
    size_t recLen = 0;

    printf("  a policy change on a key that does not load...\n");
    a.pValue = &ckTrue;
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            otherId, sizeof(otherId) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen of the other key");
    }
    if (ret == CKR_OK)
        ret = find_key_record(otherPath, sizeof(otherPath));
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_other_key_record(otherPath, recPath, sizeof(recPath));
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    /* Flip the last byte, part of the GCM tag. */
    if (ret == CKR_OK)
        ret = read_file(recPath, rec, sizeof(rec), &recLen);
    if (ret == CKR_OK && recLen > 0) {
        rec[recLen - 1] ^= 0x01;
        ret = write_file(recPath, rec, recLen);
    }
    if (ret == CKR_OK)
        ret = reopen_token_quiet(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK) {
        sret = funcList->C_SetAttributeValue(session, priv, &a, 1);
        if (sret == CKR_OK) {
            fprintf(stderr, "\npolicy change accepted - FAIL\n");
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, otherId, sizeof(otherId) - 1);
        CHECK_CKR(ret, "sign with the other key");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A key whose record does not parse refuses to sign with CKR_DEVICE_ERROR,
 * also after a logout and a login. */
static CK_RV test_unparsable_record_relogin(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-relogin";
    char recPath[512];
    static CK_BYTE rec[4096];
    size_t recLen = 0;

    printf("  a key without a usable record after a login cycle...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = read_file(recPath, rec, sizeof(rec), &recLen);
    /* Keep the length prefix intact but cut the shell short. */
    if (ret == CKR_OK && recLen > 16)
        ret = write_file(recPath, rec, 16);
    if (ret == CKR_OK)
        ret = reopen_token_quiet(&session);
    if (ret == CKR_OK) {
        funcList->C_Logout(session);
        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "login again");
    }
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR, "sign");
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Keygen defaults, a template public value, and keygen with storage off. */
static CK_RV test_keygen_defaults(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-defaults";
    static CK_BYTE value[60];
    CK_MECHANISM mech = { CKM_HSS_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_ID,             id,            sizeof(id) - 1       },
        { CKA_HSS_LEVELS,     &hssLevels,    sizeof(hssLevels)    },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
        { CKA_VALUE,          value,         sizeof(value)        },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_ID,    id,      sizeof(id) - 1 },
    };
    CK_BBOOL flags[4] = { CK_FALSE, CK_TRUE, CK_TRUE, CK_TRUE };
    CK_ATTRIBUTE get[] = {
        { CKA_SIGN,         &flags[0], sizeof(CK_BBOOL) },
        { CKA_DECRYPT,      &flags[1], sizeof(CK_BBOOL) },
        { CKA_SIGN_RECOVER, &flags[2], sizeof(CK_BBOOL) },
        { CKA_DERIVE,       &flags[3], sizeof(CK_BBOOL) },
    };
    CK_ULONG pubCount = sizeof(pubTmpl) / sizeof(*pubTmpl);

    printf("  keygen defaults, template value and storage...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubTmpl, pubCount, privTmpl, 2, NULL, 0,
            CKR_TEMPLATE_INCONSISTENT, "public key value in the template");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
            pubCount - 1, privTmpl, 2, &pub, &priv);
        CHECK_CKR(ret, "keygen without usage attributes");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, get,
            sizeof(get) / sizeof(*get));
        CHECK_CKR(ret, "read usage attributes");
    }
    if (ret == CKR_OK && (flags[0] != CK_TRUE || flags[1] != CK_FALSE ||
            flags[2] != CK_FALSE || flags[3] != CK_FALSE)) {
        fprintf(stderr, "\nprivate key usage defaults %d%d%d%d - FAIL\n",
            flags[0], flags[1], flags[2], flags[3]);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign with the default CKA_SIGN");
    }
#ifndef WOLFPKCS11_NO_ENV
    if (ret == CKR_OK) {
        setenv("WOLFPKCS11_NO_STORE", "1", 1);
        ret = gen_expect(session, pubTmpl, pubCount - 1, privTmpl, 2, NULL,
            0, CKR_DEVICE_ERROR, "keygen with storage turned off");
        unsetenv("WOLFPKCS11_NO_STORE");
    }
#endif
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Without the lock file a sign fails instead of running unserialized. */
static CK_RV test_sign_needs_lock_file(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-lock";
    DIR* d;
    struct dirent* e;
    char lockPath[512] = "";
    size_t n;

    printf("  a sign without the lock file fails...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    d = opendir(storeDir);
    while (d != NULL && (e = readdir(d)) != NULL) {
        n = strlen(e->d_name);
        if (strncmp(e->d_name, "wp11_txn_", 9) == 0 && n > 5 &&
                strcmp(e->d_name + n - 5, "_lock") == 0) {
            snprintf(lockPath, sizeof(lockPath), "%s/%s", storeDir,
                e->d_name);
        }
    }
    if (d != NULL)
        closedir(d);
    if (ret == CKR_OK && (lockPath[0] == '\0' || remove(lockPath) != 0 ||
            mkdir(lockPath, 0700) != 0)) {
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_FUNCTION_FAILED,
            "sign without the lock file");
    }
    if (lockPath[0] != '\0')
        (void)rmdir(lockPath);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign with the lock file back");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

#ifdef DEBUG_WOLFPKCS11
#ifdef __cplusplus
extern "C" {
#endif
extern int WP11_Test_StoreWriteFailOnce(int writes);
extern void WP11_Test_StoreCloseFailAfter(int closes);
extern void WP11_Test_StoreDirSyncEinval(int on);
extern void WP11_Test_SetPinStoreHook(void (*hook)(void));
extern int WP11_Test_StatefulPolicy(word64 cls, word64 type, word64 mech,
    int local, word32 flags, const byte* tmpl, int tmplLen, byte* digest);
extern int WP11_Test_StatefulRecordKey(const byte* tokenKey,
    word32 tokenKeySz, const byte* salt, byte* key);
#ifdef __cplusplus
}
#endif

/* Without directory flushing a sign fails, while other token writes still
 * succeed. */
static CK_RV test_dir_sync_einval(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-dirsync";
    char label[] = "hss-dirsync-label";
    CK_ATTRIBUTE a = { CKA_LABEL, label, sizeof(label) - 1 };

    printf("  a sign without directory flushing...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK) {
        WP11_Test_StoreDirSyncEinval(1);
        ret = funcList->C_SetAttributeValue(session, pub, &a, 1);
        CHECK_CKR(ret, "store the public key");
        if (ret == CKR_OK) {
            ret = sign_expect(session, priv, CKR_FUNCTION_FAILED,
                "sign without directory flushing");
        }
        WP11_Test_StoreDirSyncEinval(0);
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign with directory flushing back");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A destroy whose pass fails after staging the moved key's records leaves
 * the key stored where it was, so later passes and signs still work. */
static CK_RV test_sign_after_failed_move(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubA = CK_INVALID_HANDLE, privA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubB = CK_INVALID_HANDLE, privB = CK_INVALID_HANDLE;
    CK_BYTE idA[] = "hss-failmove-a";
    CK_BYTE idB[] = "hss-failmove-b";

    printf("  a sign after a failed move...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idA, sizeof(idA) - 1, &pubA, &privA);
        CHECK_CKR(ret, "keygen A");
    }
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pubB, &privB);
        CHECK_CKR(ret, "keygen B");
    }
    /* Key B moves into A's id; the token record's close, after the moved
     * object record, its key record and the old record's overwrite, fails. */
    if (ret == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(3);
        (void)funcList->C_DestroyObject(session, pubA);
        WP11_Test_StoreCloseFailAfter(-1);
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, privB, CKR_OK, "sign key B");
    if (ret == CKR_OK)
        ret = sign_expect(session, privB, CKR_OK, "sign key B again");
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idB, sizeof(idB) - 1);
        CHECK_CKR(ret, "sign key B after reload");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A key whose move failed and whose old id another object took later leaves
 * no record there for a process that still knows the key by that id. */
static CK_RV test_failed_move_old_id_reused(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubA = CK_INVALID_HANDLE, privA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubB = CK_INVALID_HANDLE, privB = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    static CK_BYTE idA[] = "hss-reuse-a";
    static CK_BYTE idB[] = "hss-reuse-b";
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BYTE aesKey[32] = { 0 };
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,    aesKey,       sizeof(aesKey)      },
    };
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_RV childRv = CKR_OK;
    int toB[2], fromB[2];
    pid_t pid;
    int status = 0;
    char c = 0;

    printf("  a failed move's old id taken by another object...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idA, sizeof(idA) - 1, &pubA, &privA);
        CHECK_CKR(ret, "keygen A");
    }
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pubB, &privB);
        CHECK_CKR(ret, "keygen B");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret != CKR_OK || pipe(toB) != 0 || pipe(fromB) != 0)
        return (ret != CKR_OK) ? ret : CKR_GENERAL_ERROR;

    pid = fork();
    if (pid == 0) {
        close(toB[1]);
        close(fromB[0]);
        if (reopen_token(&session) != CKR_OK ||
                find_by_id(session, CKO_PRIVATE_KEY, idB, sizeof(idB) - 1,
                    &privB) != CKR_OK ||
                write(fromB[1], &c, 1) != 1 || read(toB[0], &c, 1) != 1) {
            _exit(1);
        }
        childRv = hss_sign(session, privB, &sig, &sigLen);
        if (write(fromB[1], &childRv, sizeof(childRv)) !=
                (ssize_t)sizeof(childRv)) {
            _exit(2);
        }
        _exit(0);
    }
    close(toB[0]);
    close(fromB[1]);
    if (pid < 0 || read(fromB[0], &c, 1) != 1)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_PUBLIC_KEY, idA, sizeof(idA) - 1,
            &pubA);
    }
    /* Key B moves into A's id and the pass fails; the AES key then takes
     * B's old id. */
    if (ret == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(3);
        (void)funcList->C_DestroyObject(session, pubA);
        WP11_Test_StoreCloseFailAfter(-1);
        ret = funcList->C_CreateObject(session, aesTmpl,
            sizeof(aesTmpl) / sizeof(*aesTmpl), &aes);
        CHECK_CKR(ret, "create AES key");
    }
    if (write(toB[1], &c, 1) != 1 ||
            read(fromB[0], &childRv, sizeof(childRv)) !=
                (ssize_t)sizeof(childRv)) {
        ret = CKR_GENERAL_ERROR;
    }
    close(toB[1]);
    close(fromB[0]);
    if (pid > 0 && (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)) {
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK && childRv != CKR_DEVICE_ERROR) {
        fprintf(stderr, "\nsign from the old id returned %lx - FAIL\n",
            (unsigned long)childRv);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idB, sizeof(idB) - 1);
        CHECK_CKR(ret, "sign key B");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Pipes to a signer in another process, driven from the C_SetPIN hook. */
static int pinRaceGo[2] = { -1, -1 };
static int pinRaceDone[2] = { -1, -1 };
static unsigned long pinRaceLeaf = 0;

static void pin_race_hook(void)
{
    char c = 0;

    if (write(pinRaceGo[1], &c, 1) != 1 ||
            read(pinRaceDone[0], &pinRaceLeaf, sizeof(pinRaceLeaf)) !=
                (ssize_t)sizeof(pinRaceLeaf)) {
        pinRaceLeaf = 999;
    }
}

/* Another process signing between C_SetPIN's re-key and its store pass
 * leaves the key usable under the new PIN, without reusing its leaf. */
static CK_RV test_set_pin_during_sign(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-pin-race";
    static CK_UTF8CHAR newPin[] = "hss-race-user-pin";
    byte* oldPin = userPin;
    int oldPinLen = userPinLen;
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_ULONG left = 0;
    pid_t pid;
    int status = 0;
    char c = 0;

    printf("  C_SetPIN while another process signs...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret != CKR_OK || pipe(pinRaceGo) != 0 || pipe(pinRaceDone) != 0) {
        close_session(session);
        pkcs11_final();
        return (ret != CKR_OK) ? ret : CKR_GENERAL_ERROR;
    }
    pid = fork();
    if (pid == 0) {
        funcList->C_Finalize(NULL);
        if (read(pinRaceGo[0], &c, 1) != 1)
            _exit(1);
        _exit(sign_leaves(id, sizeof(id) - 1, 1, pinRaceDone[1], NULL) ==
            CKR_OK ? 0 : 1);
    }
    if (pid < 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        WP11_Test_SetPinStoreHook(pin_race_hook);
        ret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            sizeof(newPin) - 1);
        WP11_Test_SetPinStoreHook(NULL);
        CHECK_CKR(ret, "C_SetPIN");
    }
    if (pid > 0 && (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)) {
        fprintf(stderr, "\nchild signer failed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "sign after C_SetPIN");
    }
    if (ret == CKR_OK && sig_leaf(sig) <= pinRaceLeaf) {
        fprintf(stderr, "\nleaf %lu after %lu - FAIL\n", sig_leaf(sig),
            pinRaceLeaf);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    userPin = newPin;
    userPinLen = (int)sizeof(newPin) - 1;
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign with the new PIN after a reload");
    }
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &left);
    if (ret == CKR_OK && left != HSS_H5_SIGS - 3) {
        fprintf(stderr, "\n%lu left after three signatures - FAIL\n",
            (unsigned long)left);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    userPin = oldPin;
    userPinLen = oldPinLen;
    close(pinRaceGo[0]);
    close(pinRaceGo[1]);
    close(pinRaceDone[0]);
    close(pinRaceDone[1]);
    return ret;
}

/* The policy digest and the record key follow a fixed format. */
static CK_RV test_record_format(void)
{
    static const byte policyKat[32] = {
        0xdd, 0x2b, 0x00, 0x9d, 0xee, 0xd0, 0x33, 0x39,
        0xce, 0x39, 0x47, 0xe9, 0xe0, 0xb7, 0x39, 0x9c,
        0xa9, 0x5e, 0x7b, 0x9b, 0x12, 0x62, 0x40, 0x8a,
        0xfb, 0x1b, 0x06, 0x0a, 0xb7, 0x0e, 0x3a, 0x5e
    };
    static const byte keyKat[32] = {
        0x4c, 0xd0, 0xa1, 0xbb, 0x47, 0x97, 0xba, 0x9a,
        0x32, 0x65, 0x66, 0x18, 0xd8, 0x37, 0xd4, 0x99,
        0x64, 0x1f, 0x5e, 0xde, 0x32, 0xbb, 0xa5, 0x00,
        0x90, 0x53, 0xc8, 0xbd, 0x17, 0xfa, 0x5e, 0x74
    };
    byte tokenKey[32];
    byte salt[16];
    byte out[32];
    int i;
    CK_RV ret = CKR_OK;

    printf("  the record format is fixed...\n");
    if (WP11_Test_StatefulPolicy(3, 0x46, 0x4032, 1, 0x00000805,
            (const byte*)"tmpl", 4, out) != 0 ||
            XMEMCMP(out, policyKat, sizeof(out)) != 0) {
        fprintf(stderr, "\npolicy digest changed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    /* The trusted flag is not part of the policy. */
    if (ret == CKR_OK && (WP11_Test_StatefulPolicy(3, 0x46, 0x4032, 1,
            0x00000805 | 0x00000100, (const byte*)"tmpl", 4,
            out) != 0 || XMEMCMP(out, policyKat, sizeof(out)) != 0)) {
        fprintf(stderr, "\npolicy digest covers a skipped flag - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    for (i = 0; i < (int)sizeof(tokenKey); i++)
        tokenKey[i] = (byte)(i + 1);
    for (i = 0; i < (int)sizeof(salt); i++)
        salt[i] = (byte)(0x40 + i);
    if (ret == CKR_OK && (WP11_Test_StatefulRecordKey(tokenKey,
            sizeof(tokenKey), salt, out) != 0 ||
            XMEMCMP(out, keyKat, sizeof(out)) != 0)) {
        fprintf(stderr, "\nrecord key derivation changed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    return ret;
}

/* A key re-sealed by a C_SetPIN that failed is not left marked as re-sealed,
 * so losing its record later does not stop the token storing. */
static CK_RV test_failed_set_pin_lost_record(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE idA[] = "hss-pin-lost";
    CK_BYTE idB[] = "hss-pin-kept";
    CK_UTF8CHAR newPin[] = "hss-new-user-pin";
    CK_ULONG newPinLen = sizeof(newPin) - 1;
    char recPath[512];

    printf("  a lost record after a failed C_SetPIN...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idA, sizeof(idA) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen A");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen B");
    }
    if (ret == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(0);
        sret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            newPinLen);
        WP11_Test_StoreCloseFailAfter(-1);
        if (sret == CKR_OK)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK && remove(recPath) != 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            newPinLen);
        CHECK_CKR(ret, "C_SetPIN after the record was lost");
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign B");
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A failed destroy that moves a key without a record into another key's id
 * leaves that key's record in place. */
static CK_RV test_failed_destroy_keeps_record(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE idX[] = "hss-destroyed";
    CK_BYTE idK[] = "hss-recordless";
    char recX[512];
    char recK[512];
    static CK_BYTE before[8192];
    static CK_BYTE after[8192];
    size_t beforeLen = 0, afterLen = 0;

    printf("  a failed destroy keeps the record it would replace...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idX, sizeof(idX) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen X");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recX, sizeof(recX));
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idK, sizeof(idK) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen K");
    }
    if (ret == CKR_OK)
        ret = find_other_key_record(recX, recK, sizeof(recK));
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK && remove(recK) != 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, idX, sizeof(idX) - 1, &priv);
    if (ret == CKR_OK)
        ret = read_file(recX, before, sizeof(before), &beforeLen);
    /* Key K moves into X's id; the token record's close, after the moved
     * object record and its key record, fails. */
    if (ret == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(2);
        (void)funcList->C_DestroyObject(session, priv);
        WP11_Test_StoreCloseFailAfter(-1);
    }
    if (ret == CKR_OK && (read_file(recX, after, sizeof(after), &afterLen) !=
            CKR_OK || afterLen != beforeLen ||
            XMEMCMP(before, after, beforeLen) != 0)) {
        fprintf(stderr, "\nrecord of X changed by a failed destroy - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A C_SetPIN whose store pass fails keeps the old PIN, and the key signs on
 * after the state another process stored. */
static CK_RV test_set_pin_store_failure(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-pin-fail";
    CK_UTF8CHAR newPin[] = "hss-new-user-pin";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    unsigned long childLeaf = 0;
    int fds[2];
    pid_t pid;
    int status = 0;

    printf("  a failed C_SetPIN after another process signed...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "first sign");
    if (ret != CKR_OK || pipe(fds) != 0) {
        close_session(session);
        pkcs11_final();
        return (ret != CKR_OK) ? ret : CKR_GENERAL_ERROR;
    }
    pid = fork();
    if (pid == 0) {
        close(fds[0]);
        funcList->C_Finalize(NULL);
        _exit(sign_leaves(id, sizeof(id) - 1, 1, fds[1], NULL) == CKR_OK ?
            0 : 1);
    }
    close(fds[1]);
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0 ||
            read(fds[0], &childLeaf, sizeof(childLeaf)) !=
                (ssize_t)sizeof(childLeaf)) {
        fprintf(stderr, "\nchild signer failed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    close(fds[0]);
    if (ret == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(0);
        sret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            sizeof(newPin) - 1);
        WP11_Test_StoreCloseFailAfter(-1);
        if (sret == CKR_OK) {
            fprintf(stderr, "\nC_SetPIN with a failed store - FAIL\n");
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (ret == CKR_OK)
        ret = funcList->C_Logout(session);
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "login with the old PIN");
    }
    if (ret == CKR_OK)
        ret = hss_sign(session, priv, &sig, &sigLen);
    if (ret == CKR_OK && sig_leaf(sig) <= childLeaf) {
        fprintf(stderr, "\nleaf %lu not after %lu - FAIL\n", sig_leaf(sig),
            childLeaf);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = hss_verify(session, pub, sig, sigLen);
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign after reload");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* After a store pass failed and left the stored ids behind the object list,
 * a sign stores the token first instead of writing to the wrong id. */
static CK_RV test_sign_after_failed_store(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubA = CK_INVALID_HANDLE, privA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubB = CK_INVALID_HANDLE, privB = CK_INVALID_HANDLE;
    CK_BYTE idA[] = "hss-dirty-a";
    CK_BYTE idB[] = "hss-dirty-b";

    printf("  a sign after a failed store pass...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idA, sizeof(idA) - 1, &pubA, &privA);
        CHECK_CKR(ret, "keygen A");
    }
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pubB, &privB);
        CHECK_CKR(ret, "keygen B");
    }
    /* Destroying the oldest object moves key B to its id; the pass fails. */
    if (ret == CKR_OK) {
        (void)WP11_Test_StoreWriteFailOnce(0);
        (void)funcList->C_DestroyObject(session, pubA);
        (void)WP11_Test_StoreWriteFailOnce(-1);
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, privB, CKR_OK, "sign key B");
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, idB, sizeof(idB) - 1);
        CHECK_CKR(ret, "sign key B after reload");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}
/* A key left re-sealed by a failed store pass whose record is then lost does
 * not stop the token storing. */
static CK_RV test_resealed_key_record_lost(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privB = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-resealed-lost";
    static CK_BYTE idB[] = "hss-resealed-other";
    CK_BBOOL derive = CK_TRUE;
    CK_ATTRIBUTE a = { CKA_DERIVE, &derive, sizeof(derive) };
    char recPath[512];

    printf("  a re-sealed key whose record is lost...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign");
    /* The policy change re-seals the key; its store pass fails. */
    if (ret == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(0);
        (void)funcList->C_SetAttributeValue(session, priv, &a, 1);
        WP11_Test_StoreCloseFailAfter(-1);
    }
    if (ret == CKR_OK && remove(recPath) != 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            idB, sizeof(idB) - 1, &pub, &privB);
        CHECK_CKR(ret, "keygen after the lost record");
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, privB, CKR_OK, "sign with the other key");
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR, "sign lost key");
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A re-seal left pending by a failed pass survives a pass that adopts another
 * process's newer record while logged out, and is done after the next login. */
static CK_RV test_pending_reseal_after_logout(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-pending-reseal";
    static CK_BYTE label[] = "hss-pending-data";
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL derive = CK_TRUE;
    CK_ATTRIBUTE a = { CKA_DERIVE, &derive, sizeof(derive) };
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
        { CKA_LABEL,   label,      sizeof(label) - 1 },
    };
    int fds[2] = { -1, -1 };
    char go = 1;
    pid_t pid = -1;
    int status = 0;

    printf("  a pending re-seal across a logout...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign");
    /* The signer forks while nothing is pending and waits for its turn. */
    if (ret == CKR_OK && pipe(fds) != 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        pid = fork();
        if (pid == 0) {
            close(fds[1]);
            funcList->C_Finalize(NULL);
            if (read(fds[0], &go, 1) != 1)
                _exit(1);
            _exit(sign_leaves(id, sizeof(id) - 1, 1, -1, NULL) == CKR_OK ?
                0 : 1);
        }
        close(fds[0]);
        if (pid < 0)
            ret = CKR_GENERAL_ERROR;
    }
    /* The policy change re-seals the key; its store pass fails. */
    if (ret == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(0);
        (void)funcList->C_SetAttributeValue(session, priv, &a, 1);
        WP11_Test_StoreCloseFailAfter(-1);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Logout(session);
        CHECK_CKR(ret, "logout");
    }
    if (fds[1] >= 0) {
        if (ret == CKR_OK && write(fds[1], &go, 1) != 1)
            ret = CKR_GENERAL_ERROR;
        close(fds[1]);
    }
    if (pid > 0 && (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)) {
        fprintf(stderr, "\nchild signer failed - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    /* Without the token key this pass cannot re-seal the adopted record. */
    if (ret == CKR_OK) {
        (void)funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &data);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "login");
    }
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign after login");
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK) {
        ret = sign_verify_by_id(session, id, sizeof(id) - 1);
        CHECK_CKR(ret, "sign after reload");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

#endif /* DEBUG_WOLFPKCS11 */

#endif /* !_WIN32 */

static CK_RV run_all(void)
{
    CK_RV ret;

    ret = test_keygen_sign_verify();
    if (ret == CKR_OK)
        ret = test_reload_no_rollback();
    if (ret == CKR_OK)
        ret = test_keygen_negative_templates();
    if (ret == CKR_OK)
        ret = test_keys_remaining_private();
    if (ret == CKR_OK)
        ret = test_import_value_rejected();
    if (ret == CKR_OK)
        ret = test_exhaustion_poison();
    if (ret == CKR_OK)
        ret = test_sign_init_operation_active();
    if (ret == CKR_OK)
        ret = test_exhausted_key_login();
    if (ret == CKR_OK)
        ret = test_logout_login_cycle();
    if (ret == CKR_OK)
        ret = test_set_pin_reseals_state();
    if (ret == CKR_OK)
        ret = test_empty_pin_redecode();
    if (ret == CKR_OK)
        ret = test_sign_api_contract();
    if (ret == CKR_OK)
        ret = test_destroy_sibling_keeps_state();
    if (ret == CKR_OK)
        ret = test_param_matrix();
    if (ret == CKR_OK)
        ret = test_multilevel_rollover();
#ifndef _WIN32
    if (ret == CKR_OK)
        ret = test_destroy_removes_state();
    if (ret == CKR_OK)
        ret = test_destroy_older_key_removes_state();
    if (ret == CKR_OK)
        ret = test_state_tamper_detected();
    if (ret == CKR_OK)
        ret = test_write_failure_poison();
    if (ret == CKR_OK)
        ret = test_crash_durability();
    if (ret == CKR_OK)
        ret = test_corruption_matrix();
    if (ret == CKR_OK)
        ret = test_set_pin_damaged_state();
    if (ret == CKR_OK)
        ret = test_record_lost_while_loaded();
    if (ret == CKR_OK)
        ret = test_lost_record_key_moves();
    if (ret == CKR_OK)
        ret = test_unreadable_record_refuses_change();
    if (ret == CKR_OK)
        ret = test_rollback_after_adopt();
    if (ret == CKR_OK)
        ret = test_record_read_error_keeps_key();
    if (ret == CKR_OK)
        ret = test_policy_change_lost_record();
    if (ret == CKR_OK)
        ret = test_init_token_removes_state();
    if (ret == CKR_OK)
        ret = test_sign_drops_staged_state();
    if (ret == CKR_OK)
        ret = test_copy_refused();
    if (ret == CKR_OK)
        ret = test_rollback_refused();
    if (ret == CKR_OK)
        ret = test_moved_record_refused();
    if (ret == CKR_OK)
        ret = test_two_process_signing();
    if (ret == CKR_OK)
        ret = test_refresh_from_store();
    if (ret == CKR_OK)
        ret = test_store_pass_keeps_newer_state();
    if (ret == CKR_OK)
        ret = test_policy_bound_state();
    if (ret == CKR_OK)
        ret = test_set_pin_keeps_policy_binding();
    if (ret == CKR_OK)
        ret = test_move_keeps_newer_state();
    if (ret == CKR_OK)
        ret = test_moved_damaged_key();
    if (ret == CKR_OK)
        ret = test_policy_change_other_process();
    if (ret == CKR_OK)
        ret = test_sign_needs_lock_file();
    if (ret == CKR_OK)
        ret = test_stale_finalize_keeps_state();
    if (ret == CKR_OK)
        ret = test_moved_key_old_record();
    if (ret == CKR_OK)
        ret = test_policy_change_after_other_sign();
    if (ret == CKR_OK)
        ret = test_store_needs_stored_record();
    if (ret == CKR_OK)
        ret = test_policy_change_unloaded_key();
    if (ret == CKR_OK)
        ret = test_keygen_defaults();
    if (ret == CKR_OK)
        ret = test_unparsable_record_relogin();
    if (ret == CKR_OK)
        ret = test_create_missing_record();
    if (ret == CKR_OK)
        ret = test_key_class_and_single_part();
    if (ret == CKR_OK)
        ret = test_params_without_login();

#ifdef DEBUG_WOLFPKCS11
    if (ret == CKR_OK)
        ret = test_dir_sync_einval();
    if (ret == CKR_OK)
        ret = test_sign_after_failed_store();
    if (ret == CKR_OK)
        ret = test_sign_after_failed_move();
    if (ret == CKR_OK)
        ret = test_failed_move_old_id_reused();
    if (ret == CKR_OK)
        ret = test_record_format();
    if (ret == CKR_OK)
        ret = test_set_pin_during_sign();
    if (ret == CKR_OK)
        ret = test_set_pin_store_failure();
    if (ret == CKR_OK)
        ret = test_failed_destroy_keeps_record();
    if (ret == CKR_OK)
        ret = test_failed_set_pin_lost_record();
    if (ret == CKR_OK)
        ret = test_resealed_key_record_lost();
    if (ret == CKR_OK)
        ret = test_pending_reseal_after_logout();
#endif
#ifdef DEBUG_WOLFPKCS11
    if (ret == CKR_OK)
        ret = test_keygen_set_pin_race();
#endif
#endif
    return ret;
}
#endif /* WOLFPKCS11_LMS_PRIVATE && file store */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
#if defined(WOLFPKCS11_LMS_PRIVATE) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_TPM_STORE)
    {
        CK_RV ret;

#ifndef WOLFPKCS11_NO_ENV
        XSETENV("WOLFPKCS11_TOKEN_PATH", storeDir, 1);
#endif

        printf("wolfPKCS11 LMS/HSS private-key (sign) test\n");
        printf("=========================================\n\n");

        ret = run_all();

        cleanup_store();
        if (ret == CKR_OK) {
            printf("\nAll tests passed!\n");
            return 0;
        }
        printf("\nTest failed with error: %lx\n", (unsigned long)ret);
        return 1;
    }
#else
    printf("LMS/HSS sign support (--enable-lms-private) not compiled in!\n");
    return 77;
#endif
}
