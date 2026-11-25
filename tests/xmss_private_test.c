/* xmss_private_test.c
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
 * Tests for XMSS and XMSS^MT keygen and signing (--enable-xmss-private).
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
#include <stdlib.h>
#include <string.h>

/* The tests point the token at their own store directory. */
#if defined(WOLFPKCS11_XMSS_PRIVATE) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_TPM_STORE) && \
    !defined(WOLFPKCS11_NO_ENV) && !defined(_WIN32)

#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#if !defined(SINGLE_THREADED) && !defined(WOLFPKCS11_SINGLE_THREADED)
    #include <pthread.h>
    #define XMSS_TEST_THREADS
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
        if ((rv) != CKR_OK) {                                              \
            fprintf(stderr, "\n%s:%d - %s: %lx - FAIL\n",                  \
                    __FILE__, __LINE__, msg, (unsigned long)(rv));         \
        }                                                                  \
    }                                                                      \
    while (0)

#define CHECK_CKR_FAIL(rv, expected, msg)                                  \
    do {                                                                   \
        if ((rv) != (expected)) {                                          \
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
static const char* storeDir = "./store/xmss_priv";

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

/* XMSS-SHA2_10_256: one tree; wolfSSL keeps the last of 1024 leaves. */
#define XMSS_SHA2_10_256          0x00000001UL
#define XMSS_SHA2_10_256_SIGS     1023UL
/* XMSSMT-SHA2_20/4_256: four layers of height 5, cheap to generate. */
#define XMSSMT_SHA2_20_4_256      0x00000002UL
#define XMSSMT_SHA2_20_4_256_SIGS ((1UL << 20) - 1)
/* Hash sizes of 24 and 64 bytes, which a wolfSSL build may leave out. */
#define XMSS_SHA2_10_192          0x0000000DUL
#define XMSS_SHA2_10_512          0x00000004UL

static const CK_BYTE testMsg[] = "wolfPKCS11 XMSS private-key sign test";
#define TEST_MSG_LEN ((CK_ULONG)(sizeof(testMsg) - 1))

typedef struct XmssScheme {
    const char* name;
    CK_MECHANISM_TYPE genMech;
    CK_MECHANISM_TYPE sigMech;
    CK_ULONG paramSet;
    CK_ULONG sigs;
    int idxLen;                       /* Bytes of the leaf index in a sig */
    int optional;                     /* Skipped when the build lacks it */
} XmssScheme;

static const XmssScheme xmss = {
    "XMSS", CKM_XMSS_KEY_PAIR_GEN, CKM_XMSS, XMSS_SHA2_10_256,
    XMSS_SHA2_10_256_SIGS, 4, 0
};
static const XmssScheme xmss192 = {
    "XMSS-SHA2_10_192", CKM_XMSS_KEY_PAIR_GEN, CKM_XMSS, XMSS_SHA2_10_192,
    XMSS_SHA2_10_256_SIGS, 4, 1
};
static const XmssScheme xmss512 = {
    "XMSS-SHA2_10_512", CKM_XMSS_KEY_PAIR_GEN, CKM_XMSS, XMSS_SHA2_10_512,
    XMSS_SHA2_10_256_SIGS, 4, 1
};
static const XmssScheme xmssmt = {
    "XMSS^MT", CKM_XMSSMT_KEY_PAIR_GEN, CKM_XMSSMT, XMSSMT_SHA2_20_4_256,
    XMSSMT_SHA2_20_4_256_SIGS, 3, 0
};

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
#else
    ret = C_GetFunctionList(&funcList);
#endif
    if (ret != CKR_OK)
        return ret;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    CHECK_CKR(ret, "Initialize");
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
        CHECK_CKR(ret, "Get Slot List");
    }
    if (ret == CKR_OK && slotCount == 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK)
        slot = slotList[0];
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

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;

    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
        NULL, NULL, session);
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

/* Fresh library, token and user PIN, and a logged-in R/W session. */
static CK_RV fresh_token(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    CK_SESSION_HANDLE so = CK_INVALID_HANDLE;
    unsigned char label[32];

    cleanup_store();
    ret = pkcs11_init();
    if (ret == CKR_OK) {
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenName, strlen(tokenName));
        ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
        CHECK_CKR(ret, "Init Token");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot,
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &so);
    }
    if (ret == CKR_OK)
        ret = funcList->C_Login(so, CKU_SO, soPin, soPinLen);
    if (ret == CKR_OK) {
        ret = funcList->C_InitPIN(so, userPin, userPinLen);
        CHECK_CKR(ret, "Init User PIN");
    }
    close_session(so);
    if (ret == CKR_OK)
        ret = pkcs11_open_session(session);
    return ret;
}

static CK_RV reopen_token(CK_SESSION_HANDLE* session)
{
    CK_RV ret;

    ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = pkcs11_open_session(session);
    return ret;
}

static CK_RV gen_key(CK_SESSION_HANDLE session, const XmssScheme* s,
    CK_BYTE* id, CK_ULONG idLen, CK_OBJECT_HANDLE* pub,
    CK_OBJECT_HANDLE* priv)
{
    CK_MECHANISM mech = { 0, NULL, 0 };
    CK_ULONG paramSet = s->paramSet;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,         &ckTrue,   sizeof(ckTrue)   },
        { CKA_VERIFY,        &ckTrue,   sizeof(ckTrue)   },
        { CKA_ID,            id,        idLen            },
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_SIGN,  &ckTrue, sizeof(ckTrue) },
        { CKA_ID,    id,      idLen          },
    };

    mech.mechanism = s->genMech;
    return funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
        sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
        sizeof(privTmpl) / sizeof(*privTmpl), pub, priv);
}

static CK_RV find_by_id(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls,
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
    if (ret == CKR_OK && count != 1) {
        fprintf(stderr, "\nExpected 1 object with the given CKA_ID - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    return ret;
}

/* Sign msg with a length query first; the caller frees *sigOut. */
static CK_RV xmss_sign_msg(CK_SESSION_HANDLE session, const XmssScheme* s,
    CK_OBJECT_HANDLE priv, const CK_BYTE* msg, CK_ULONG msgLen,
    CK_BYTE** sigOut, CK_ULONG* sigLenOut)
{
    CK_RV ret;
    CK_MECHANISM mech = { 0, NULL, 0 };
    CK_ULONG sigLen = 0;
    CK_BYTE* sig = NULL;

    mech.mechanism = s->sigMech;
    ret = funcList->C_SignInit(session, &mech, priv);
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, (CK_BYTE*)msg, msgLen, NULL,
            &sigLen);
    }
    if (ret == CKR_OK && sigLen == 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        sig = (CK_BYTE*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL)
            ret = CKR_HOST_MEMORY;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, (CK_BYTE*)msg, msgLen, sig,
            &sigLen);
    }
    if (ret == CKR_OK) {
        *sigOut = sig;
        *sigLenOut = sigLen;
    }
    else if (sig != NULL) {
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

static CK_RV xmss_sign(CK_SESSION_HANDLE session, const XmssScheme* s,
    CK_OBJECT_HANDLE priv, CK_BYTE** sigOut, CK_ULONG* sigLenOut)
{
    return xmss_sign_msg(session, s, priv, testMsg, TEST_MSG_LEN, sigOut,
        sigLenOut);
}

static CK_RV xmss_verify_msg(CK_SESSION_HANDLE session, const XmssScheme* s,
    CK_OBJECT_HANDLE pub, const CK_BYTE* msg, CK_ULONG msgLen, CK_BYTE* sig,
    CK_ULONG sigLen)
{
    CK_RV ret;
    CK_MECHANISM mech = { 0, NULL, 0 };

    mech.mechanism = s->sigMech;
    ret = funcList->C_VerifyInit(session, &mech, pub);
    if (ret == CKR_OK)
        ret = funcList->C_Verify(session, (CK_BYTE*)msg, msgLen, sig, sigLen);
    return ret;
}

static CK_RV get_ulong(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, CK_ULONG* value)
{
    CK_ATTRIBUTE a;

    a.type = type;
    a.pValue = value;
    a.ulValueLen = sizeof(*value);
    return funcList->C_GetAttributeValue(session, obj, &a, 1);
}

static unsigned long sig_index(const XmssScheme* s, const CK_BYTE* sig)
{
    unsigned long idx = 0;
    int i;

    for (i = 0; i < s->idxLen; i++)
        idx = (idx << 8) | sig[i];
    return idx;
}

/* Sign, verify and check the index the signature used. */
static CK_RV sign_check(CK_SESSION_HANDLE session, const XmssScheme* s,
    CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv, unsigned long expIdx)
{
    CK_RV ret;
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;

    ret = xmss_sign(session, s, priv, &sig, &sigLen);
    CHECK_CKR(ret, "C_Sign");
    if (ret == CKR_OK) {
        ret = xmss_verify_msg(session, s, pub, testMsg, TEST_MSG_LEN, sig,
            sigLen);
        CHECK_CKR(ret, "C_Verify of generated signature");
    }
    if (ret == CKR_OK && sig_index(s, sig) != expIdx) {
        fprintf(stderr, "\n%s signature index %lu, expected %lu - FAIL\n",
            s->name, sig_index(s, sig), expIdx);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Keygen, sign, verify, and the private key attributes. */
static CK_RV test_keygen_sign_verify(const XmssScheme* s)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-ksv";
    CK_ULONG v = 0;
    CK_BYTE value[16];
    CK_ATTRIBUTE a = { CKA_VALUE, value, sizeof(value) };
    CK_BBOOL flags[4] = { CK_FALSE, CK_TRUE, CK_FALSE, CK_FALSE };
    CK_ATTRIBUTE prot[] = {
        { CKA_SENSITIVE,         &flags[0], sizeof(CK_BBOOL) },
        { CKA_EXTRACTABLE,       &flags[1], sizeof(CK_BBOOL) },
        { CKA_ALWAYS_SENSITIVE,  &flags[2], sizeof(CK_BBOOL) },
        { CKA_NEVER_EXTRACTABLE, &flags[3], sizeof(CK_BBOOL) },
    };

    printf("  %s keygen -> sign -> verify, attributes...\n", s->name);
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_key(session, s, id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    if (ret == CKR_OK) {
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &v);
        CHECK_CKR(ret, "CKA_KEYS_REMAINING");
    }
    if (ret == CKR_OK && v != s->sigs) {
        fprintf(stderr, "\nkeys remaining %lu, expected %lu - FAIL\n", v,
            s->sigs);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = sign_check(session, s, pub, priv, 0);
    if (ret == CKR_OK)
        ret = sign_check(session, s, pub, priv, 1);
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &v);
    if (ret == CKR_OK && v != s->sigs - 2) {
        fprintf(stderr, "\nkeys remaining after two signatures %lu - FAIL\n",
            v);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = get_ulong(session, priv, CKA_PARAMETER_SET, &v);
        CHECK_CKR(ret, "private CKA_PARAMETER_SET");
    }
    if (ret == CKR_OK && v != s->paramSet) {
        fprintf(stderr, "\nprivate CKA_PARAMETER_SET %lx - FAIL\n", v);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = get_ulong(session, pub, CKA_PARAMETER_SET, &v);
    if (ret == CKR_OK && v != s->paramSet) {
        fprintf(stderr, "\npublic CKA_PARAMETER_SET %lx - FAIL\n", v);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        v = funcList->C_GetAttributeValue(session, priv, &a, 1);
        if (v != CKR_ATTRIBUTE_SENSITIVE ||
                a.ulValueLen != CK_UNAVAILABLE_INFORMATION) {
            fprintf(stderr, "\nprivate CKA_VALUE read: %lx - FAIL\n", v);
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, prot,
            sizeof(prot) / sizeof(*prot));
        CHECK_CKR(ret, "read protection attributes");
    }
    if (ret == CKR_OK && (flags[0] != CK_TRUE || flags[1] != CK_FALSE ||
            flags[2] != CK_TRUE || flags[3] != CK_TRUE)) {
        fprintf(stderr, "\nprivate key protection %d%d%d%d - FAIL\n",
            flags[0], flags[1], flags[2], flags[3]);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* The state survives a reload with no index reused. */
static CK_RV test_reload_no_reuse(const XmssScheme* s)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-reload";
    unsigned long i;
    int skip = 0;

    printf("  %s state survives a reload...\n", s->name);
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_key(session, s, id, sizeof(id) - 1, &pub, &priv);
        if (ret == CKR_PARAMETER_SET_NOT_SUPPORTED && s->optional) {
            printf("    not in this wolfSSL build, skipped\n");
            skip = 1;
            ret = CKR_OK;
        }
    }
    for (i = 0; ret == CKR_OK && !skip && i < 3; i++)
        ret = sign_check(session, s, pub, priv, i);
    close_session(session);
    pkcs11_final();
    session = CK_INVALID_HANDLE;
    if (skip)
        return ret;

    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, s, pub, priv, 3);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* An empty message signs and verifies like any other. */
static CK_RV test_empty_message(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-empty";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;

    printf("  XMSS signs an empty message...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK) {
        ret = xmss_sign_msg(session, &xmss, priv, testMsg, 0, &sig, &sigLen);
        CHECK_CKR(ret, "C_Sign of an empty message");
    }
    if (ret == CKR_OK) {
        ret = xmss_verify_msg(session, &xmss, pub, testMsg, 0, sig, sigLen);
        CHECK_CKR(ret, "C_Verify of an empty message");
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

static CK_RV gen_expect(CK_SESSION_HANDLE session, CK_MECHANISM_TYPE type,
    CK_ATTRIBUTE* pubTmpl, CK_ULONG pubCnt, CK_ATTRIBUTE* privTmpl,
    CK_ULONG privCnt, CK_RV expected, const char* msg)
{
    CK_RV rv;
    CK_MECHANISM mech = { 0, NULL, 0 };
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;

    mech.mechanism = type;
    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl, pubCnt,
        privTmpl, privCnt, &pub, &priv);
    CHECK_CKR_FAIL(rv, expected, msg);
    return (rv == expected) ? CKR_OK : CKR_GENERAL_ERROR;
}

static CK_RV test_keygen_negative(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_ULONG good = XMSS_SHA2_10_256;
    CK_ULONG bad = 0x7777UL;
    CK_ULONG other = 0x00000002UL;
    CK_BYTE value[68];
    CK_MECHANISM mech = { CKM_XMSS_KEY_PAIR_GEN, value, 1 };
    CK_OBJECT_HANDLE pub, priv;
    CK_ATTRIBUTE pubNoParam[] = {
        { CKA_VERIFY, &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE pubGood[] = {
        { CKA_PARAMETER_SET, &good, sizeof(good) },
    };
    CK_ATTRIBUTE pubBad[] = {
        { CKA_PARAMETER_SET, &bad, sizeof(bad) },
    };
    CK_ATTRIBUTE pubValue[] = {
        { CKA_PARAMETER_SET, &good,  sizeof(good)  },
        { CKA_VALUE,         value,  sizeof(value) },
    };
    CK_ATTRIBUTE privToken[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE privSession[] = {
        { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
    };
    CK_ATTRIBUTE privCopyable[] = {
        { CKA_TOKEN,    &ckTrue, sizeof(ckTrue) },
        { CKA_COPYABLE, &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE privNotSensitive[] = {
        { CKA_TOKEN,     &ckTrue,  sizeof(ckTrue)  },
        { CKA_SENSITIVE, &ckFalse, sizeof(ckFalse) },
    };
    CK_ATTRIBUTE privExtractable[] = {
        { CKA_TOKEN,       &ckTrue, sizeof(ckTrue) },
        { CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE privValue[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_VALUE, value,   sizeof(value)  },
    };
    CK_ATTRIBUTE privOther[] = {
        { CKA_TOKEN,         &ckTrue, sizeof(ckTrue) },
        { CKA_PARAMETER_SET, &other,  sizeof(other)  },
    };

    printf("  keygen refuses bad templates...\n");
    XMEMSET(value, 0, sizeof(value));
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_expect(session, CKM_XMSS_KEY_PAIR_GEN, pubNoParam, 1,
            privToken, 1, CKR_TEMPLATE_INCOMPLETE, "no CKA_PARAMETER_SET");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, CKM_XMSS_KEY_PAIR_GEN, pubBad, 1,
            privToken, 1, CKR_PARAMETER_SET_NOT_SUPPORTED,
            "unknown parameter set");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, CKM_XMSSMT_KEY_PAIR_GEN, pubBad, 1,
            privToken, 1, CKR_PARAMETER_SET_NOT_SUPPORTED,
            "unknown XMSS^MT parameter set");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, CKM_XMSS_KEY_PAIR_GEN, pubGood, 1,
            privSession, 1, CKR_TEMPLATE_INCONSISTENT,
            "session private key");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, CKM_XMSS_KEY_PAIR_GEN, pubGood, 1,
            privCopyable, 2, CKR_TEMPLATE_INCONSISTENT,
            "copyable private key");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, CKM_XMSS_KEY_PAIR_GEN, pubGood, 1,
            privNotSensitive, 2, CKR_TEMPLATE_INCONSISTENT,
            "private key not sensitive");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, CKM_XMSS_KEY_PAIR_GEN, pubGood, 1,
            privExtractable, 2, CKR_TEMPLATE_INCONSISTENT,
            "extractable private key");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, CKM_XMSS_KEY_PAIR_GEN, pubValue, 2,
            privToken, 1, CKR_TEMPLATE_INCONSISTENT, "public key value");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, CKM_XMSS_KEY_PAIR_GEN, pubGood, 1,
            privValue, 2, CKR_TEMPLATE_INCONSISTENT, "private key value");
    }
    if (ret == CKR_OK) {
        ret = gen_expect(session, CKM_XMSS_KEY_PAIR_GEN, pubGood, 1,
            privOther, 2, CKR_TEMPLATE_INCONSISTENT,
            "templates disagree on the parameter set");
    }
    if (ret == CKR_OK) {
        CK_RV rv = funcList->C_GenerateKeyPair(session, &mech, pubGood, 1,
            privToken, 1, &pub, &priv);
        CHECK_CKR_FAIL(rv, CKR_MECHANISM_PARAM_INVALID, "mechanism param");
        if (rv != CKR_MECHANISM_PARAM_INVALID)
            ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Private keys are neither imported nor copied, and only sign. */
static CK_RV test_import_copy_refused(void)
{
    CK_RV ret, rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-copy";
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_XMSS;
    CK_ULONG param = XMSS_SHA2_10_256;
    CK_BYTE value[132];
    CK_MECHANISM mech = { CKM_XMSSMT, NULL, 0 };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,         &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE,      &keyType,   sizeof(keyType)   },
        { CKA_TOKEN,         &ckTrue,    sizeof(ckTrue)    },
        { CKA_PARAMETER_SET, &param,     sizeof(param)     },
        { CKA_VALUE,         value,      sizeof(value)     },
    };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,         &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,      &keyType,  sizeof(keyType)  },
        { CKA_PARAMETER_SET, &param,    sizeof(param)    },
    };

    printf("  private keys are not imported, copied or used to verify...\n");
    XMEMSET(value, 0, sizeof(value));
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        rv = funcList->C_CreateObject(session, privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &obj);
        CHECK_CKR_FAIL(rv, CKR_ATTRIBUTE_VALUE_INVALID, "private import");
        if (rv != CKR_ATTRIBUTE_VALUE_INVALID)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        rv = funcList->C_CreateObject(session, pubTmpl,
            sizeof(pubTmpl) / sizeof(*pubTmpl), &obj);
        CHECK_CKR_FAIL(rv, CKR_ATTRIBUTE_VALUE_INVALID,
            "public import without a value");
        if (rv != CKR_ATTRIBUTE_VALUE_INVALID)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK) {
        rv = funcList->C_CopyObject(session, priv, NULL, 0, &obj);
        CHECK_CKR_FAIL(rv, CKR_ACTION_PROHIBITED, "C_CopyObject");
        if (rv != CKR_ACTION_PROHIBITED)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        rv = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(rv, CKR_KEY_TYPE_INCONSISTENT,
            "XMSS^MT mechanism with an XMSS key");
        if (rv != CKR_KEY_TYPE_INCONSISTENT)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        mech.mechanism = CKM_XMSS;
        rv = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
            "verify with the private key");
        if (rv != CKR_KEY_FUNCTION_NOT_PERMITTED)
            ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

static CK_RV find_key_record(char* path, size_t pathLen)
{
    DIR* d;
    struct dirent* e;
    CK_RV ret = CKR_OBJECT_HANDLE_INVALID;
    const char* prefix = "wp11_xmsskey_priv_";

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

static CK_RV sign_expect(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
    CK_RV expected, const char* msg)
{
    CK_RV rv;
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;

    rv = xmss_sign(session, &xmss, priv, &sig, &sigLen);
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    CHECK_CKR_FAIL(rv, expected, msg);
    return (rv == expected) ? CKR_OK : CKR_GENERAL_ERROR;
}

/* A stored state moved back, while loaded or across a reload, is refused. */
static CK_RV test_rollback_refused(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-rollback";
    char recPath[512];
    static CK_BYTE saved[65536];
    size_t savedLen = 0;

    printf("  XMSS state moved back is refused...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK)
        ret = find_key_record(recPath, sizeof(recPath));
    if (ret == CKR_OK)
        ret = read_file(recPath, saved, sizeof(saved), &savedLen);
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign");
    if (ret == CKR_OK)
        ret = write_file(recPath, saved, savedLen);
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_DEVICE_ERROR,
            "sign after rollback");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* C_SetPIN re-seals the state, which signs under the new PIN. */
static CK_RV test_set_pin_reseals(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-setpin";
    byte* oldPin = userPin;
    int oldPinLen = userPinLen;
    static byte newPin[] = "xmss-new-user-pin";

    printf("  XMSS state signs after C_SetPIN...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 0);
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, oldPin, oldPinLen, newPin,
            (CK_ULONG)(sizeof(newPin) - 1));
        CHECK_CKR(ret, "C_SetPIN");
    }
    close_session(session);
    pkcs11_final();
    session = CK_INVALID_HANDLE;

    userPin = newPin;
    userPinLen = (int)(sizeof(newPin) - 1);
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 1);
    close_session(session);
    pkcs11_final();
    userPin = oldPin;
    userPinLen = oldPinLen;
    return ret;
}

/* XMSS private key records that still hold a state. */
static int count_live_records(void)
{
    DIR* d;
    struct dirent* e;
    struct stat st;
    char path[512];
    int cnt = 0;
    const char* prefix = "wp11_xmsskey_priv_";

    d = opendir(storeDir);
    if (d == NULL)
        return -1;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, strlen(prefix)) != 0)
            continue;
        snprintf(path, sizeof(path), "%s/%s", storeDir, e->d_name);
        /* A record that holds no state is 12 zero bytes after the length. */
        if (stat(path, &st) == 0 && st.st_size > 16)
            cnt++;
    }
    closedir(d);
    return cnt;
}

static CK_RV create_data_object(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE* obj)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BYTE value[] = "xmss-data";
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls,    sizeof(cls)       },
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue)    },
        { CKA_VALUE, value,   sizeof(value) - 1 },
    };

    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), obj);
}

static CK_RV expect_live_records(int expected, const char* msg)
{
    int cnt = count_live_records();

    if (cnt != expected) {
        fprintf(stderr, "\n%s: %d XMSS records hold a state, expected %d - "
            "FAIL\n", msg, cnt, expected);
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

/* C_DestroyObject leaves no state of the key behind. */
static CK_RV test_destroy_removes_record(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-destroy";

    printf("  XMSS key destroy removes its state...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 0);
    if (ret == CKR_OK)
        ret = expect_live_records(1, "after keygen");
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, priv);
        CHECK_CKR(ret, "C_DestroyObject");
    }
    if (ret == CKR_OK)
        ret = expect_live_records(0, "after destroy");
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A destroy that moves the key into the freed id keeps its state. */
static CK_RV test_move_keeps_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-move";

    printf("  XMSS key moved by a destroy keeps its state...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = create_data_object(session, &data);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 0);
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, data);
        CHECK_CKR(ret, "destroy the oldest object");
    }
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 1);
    if (ret == CKR_OK)
        ret = expect_live_records(1, "after the move");
    close_session(session);
    pkcs11_final();
    session = CK_INVALID_HANDLE;

    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 2);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A policy change re-seals the state, which keeps signing. */
static CK_RV test_policy_change(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-policy";
    CK_ATTRIBUTE a = { CKA_DERIVE, &ckTrue, sizeof(ckTrue) };

    printf("  XMSS key signs after a policy change...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 0);
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, priv, &a, 1);
        CHECK_CKR(ret, "change CKA_DERIVE");
    }
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 1);
    close_session(session);
    pkcs11_final();
    session = CK_INVALID_HANDLE;

    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 2);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* An XMSS^MT key reports its attributes after a reload, before it signs. */
static CK_RV test_mt_attributes_after_reload(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmssmt-attr";
    CK_ULONG v = 0;

    printf("  XMSS^MT attributes after a reload...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmssmt, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmssmt, pub, priv, 0);
    close_session(session);
    pkcs11_final();
    session = CK_INVALID_HANDLE;

    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_PARAMETER_SET, &v);
    if (ret == CKR_OK && v != xmssmt.paramSet) {
        fprintf(stderr, "\nCKA_PARAMETER_SET %lx after reload - FAIL\n", v);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &v);
    if (ret == CKR_OK && v != xmssmt.sigs - 1) {
        fprintf(stderr, "\nkeys remaining %lu after reload - FAIL\n", v);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = sign_check(session, &xmssmt, pub, priv, 1);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* After a state write fails, the next signature reloads the stored state. */
static CK_RV test_write_failure_recovers(void)
{
    CK_RV ret, rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-wfail";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    struct stat dirStat;
    CK_ULONG v = 0;

    printf("  XMSS key signs again after a failed state write...\n");
    if (geteuid() == 0) {
        printf("    skipped: root ignores the read-only directory\n");
        return CKR_OK;
    }
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 0);
    if (ret == CKR_OK &&
            (stat(storeDir, &dirStat) != 0 || chmod(storeDir, 0500) != 0)) {
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        rv = xmss_sign(session, &xmss, priv, &sig, &sigLen);
        (void)chmod(storeDir, dirStat.st_mode);
        if (rv == CKR_OK) {
            fprintf(stderr, "\nsigned with an unwritable store - FAIL\n");
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 1);
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &v);
    if (ret == CKR_OK && v != xmss.sigs - 2) {
        fprintf(stderr, "\nkeys remaining %lu after recovery - FAIL\n", v);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A logout scrubs the key and a login decodes it again. */
static CK_RV test_logout_login(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-relogin";
    CK_ULONG v = 0;

    printf("  XMSS key signs after a logout and login...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 0);
    if (ret == CKR_OK)
        ret = funcList->C_Logout(session);
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "login again");
    }
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_PARAMETER_SET, &v);
    if (ret == CKR_OK && v != xmss.paramSet) {
        fprintf(stderr, "\nCKA_PARAMETER_SET %lx after login - FAIL\n", v);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 1);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A key a logout scrubbed reports no remaining signatures. */
static CK_RV test_keys_remaining_logged_out(void)
{
    CK_RV ret, rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_XMSS_KEY_PAIR_GEN, NULL, 0 };
    CK_ULONG paramSet = XMSS_SHA2_10_256;
    CK_ULONG v = 0;
    CK_ATTRIBUTE a = { CKA_KEYS_REMAINING, &v, sizeof(v) };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,         &ckTrue,   sizeof(ckTrue)   },
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
    };
    /* A public object, so it stays readable after the logout. */
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &ckTrue,  sizeof(ckTrue)  },
        { CKA_PRIVATE, &ckFalse, sizeof(ckFalse) },
    };

    printf("  XMSS keys remaining while logged out...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, &mech, pubTmpl, 2,
            privTmpl, 2, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = funcList->C_Logout(session);
    if (ret == CKR_OK) {
        rv = funcList->C_GetAttributeValue(session, priv, &a, 1);
        if (rv == CKR_OK || a.ulValueLen != CK_UNAVAILABLE_INFORMATION) {
            fprintf(stderr, "\nkeys remaining while logged out: %lx, %lu - "
                "FAIL\n", (unsigned long)rv, (unsigned long)a.ulValueLen);
            ret = CKR_GENERAL_ERROR;
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "login again");
    }
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &v);
    if (ret == CKR_OK && v != xmss.sigs) {
        fprintf(stderr, "\nkeys remaining %lu after login - FAIL\n", v);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Key class checks, single-part signing only, and keygen needs a login. */
static CK_RV test_key_class_and_single_part(void)
{
    CK_RV ret, rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub2 = CK_INVALID_HANDLE, priv2 = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-key-class";
    CK_ATTRIBUTE verify = { CKA_VERIFY, &ckTrue, sizeof(ckTrue) };
    CK_ATTRIBUTE sign = { CKA_SIGN, &ckTrue, sizeof(ckTrue) };
    CK_MECHANISM mech = { CKM_XMSS, NULL, 0 };
    CK_MECHANISM genMech = { CKM_XMSS_KEY_PAIR_GEN, NULL, 0 };
    CK_ULONG paramSet = XMSS_SHA2_10_256;
    CK_ULONG before = 0, after = 0;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,         &ckTrue,   sizeof(ckTrue)   },
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
    };
    /* A public object, so only the keygen login check refuses it. */
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &ckTrue,  sizeof(ckTrue)  },
        { CKA_PRIVATE, &ckFalse, sizeof(ckFalse) },
    };

    printf("  XMSS key class checks and single-part signing...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, priv, &verify, 1);
        CHECK_CKR(ret, "set CKA_VERIFY on the private key");
    }
    if (ret == CKR_OK) {
        rv = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(rv, CKR_KEY_TYPE_INCONSISTENT,
            "C_VerifyInit with the private key");
        if (rv != CKR_KEY_TYPE_INCONSISTENT)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, pub, &sign, 1);
        CHECK_CKR(ret, "set CKA_SIGN on the public key");
    }
    if (ret == CKR_OK) {
        rv = funcList->C_SignInit(session, &mech, pub);
        CHECK_CKR_FAIL(rv, CKR_KEY_TYPE_INCONSISTENT,
            "C_SignInit with the public key");
        if (rv != CKR_KEY_TYPE_INCONSISTENT)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &before);
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR(ret, "C_SignInit with the private key");
    }
    if (ret == CKR_OK) {
        rv = funcList->C_SignUpdate(session, (CK_BYTE*)testMsg, TEST_MSG_LEN);
        CHECK_CKR_FAIL(rv, CKR_MECHANISM_INVALID, "C_SignUpdate");
        if (rv != CKR_MECHANISM_INVALID)
            ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &after);
    if (ret == CKR_OK && after != before) {
        fprintf(stderr, "\nC_SignUpdate used a leaf - FAIL\n");
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Logout(session);
        CHECK_CKR(ret, "C_Logout");
    }
    if (ret == CKR_OK) {
        rv = funcList->C_GenerateKeyPair(session, &genMech, pubTmpl, 2,
            privTmpl, 2, &pub2, &priv2);
        CHECK_CKR_FAIL(rv, CKR_USER_NOT_LOGGED_IN, "keygen without login");
        if (rv != CKR_USER_NOT_LOGGED_IN)
            ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* After C_SetPIN the key signs in the same session from the re-sealed state. */
static CK_RV test_set_pin_same_session(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-setpin2";
    static byte newPin[] = "xmss-other-user-pin";

    printf("  XMSS key signs after C_SetPIN in the same session...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 0);
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(session, userPin, userPinLen, newPin,
            (CK_ULONG)(sizeof(newPin) - 1));
        CHECK_CKR(ret, "C_SetPIN");
    }
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 1);
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 2);
    close_session(session);
    pkcs11_final();
    return ret;
}

#ifdef WOLFPKCS11_LMS_PRIVATE
/* HSS and XMSS keys keep separate states on one token. */
static CK_RV test_mixed_token(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hssPub = CK_INVALID_HANDLE, hssPriv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-mixed";
    CK_BYTE hssId[] = "hss-mixed";
    CK_ULONG levels = 1;
    CK_ULONG lmsType = CKL_LMS_SHA256_M32_H5;
    CK_ULONG lmotsType = CKL_LMOTS_SHA256_N32_W4;
    CK_MECHANISM mech = { CKM_HSS_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE hssPubTmpl[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue)    },
        { CKA_ID,    hssId,   sizeof(hssId) - 1 },
    };
    CK_ATTRIBUTE hssPrivTmpl[] = {
        { CKA_TOKEN,           &ckTrue,    sizeof(ckTrue)    },
        { CKA_ID,              hssId,      sizeof(hssId) - 1 },
        { CKA_HSS_LEVELS,      &levels,    sizeof(levels)    },
        { CKA_HSS_LMS_TYPES,   &lmsType,   sizeof(lmsType)   },
        { CKA_HSS_LMOTS_TYPES, &lmotsType, sizeof(lmotsType) },
    };
    CK_ULONG v = 0;

    printf("  HSS and XMSS keys on one token...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, &mech, hssPubTmpl,
            sizeof(hssPubTmpl) / sizeof(*hssPubTmpl), hssPrivTmpl,
            sizeof(hssPrivTmpl) / sizeof(*hssPrivTmpl), &hssPub, &hssPriv);
        CHECK_CKR(ret, "HSS keygen");
    }
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 0);
    close_session(session);
    pkcs11_final();
    session = CK_INVALID_HANDLE;

    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_PRIVATE_KEY, hssId, sizeof(hssId) - 1,
            &hssPriv);
    }
    if (ret == CKR_OK)
        ret = sign_check(session, &xmss, pub, priv, 1);
    if (ret == CKR_OK)
        ret = get_ulong(session, hssPriv, CKA_KEYS_REMAINING, &v);
    if (ret == CKR_OK && v != 32) {
        fprintf(stderr, "\nHSS keys remaining %lu - FAIL\n", v);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* An XMSS key moved in the same store pass that puts an HSS key at its old
 * id leaves no state at that id. */
static CK_RV test_mixed_move(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hssPub = CK_INVALID_HANDLE, hssPriv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-mixmove";
    CK_ULONG levels = 1;
    CK_ULONG lmsType = CKL_LMS_SHA256_M32_H5;
    CK_ULONG lmotsType = CKL_LMOTS_SHA256_N32_W4;
    CK_MECHANISM mech = { CKM_HSS_KEY_PAIR_GEN, NULL, 0 };
    /* A session public key keeps the keygen to one store pass. */
    CK_ATTRIBUTE hssPubTmpl[] = {
        { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
    };
    CK_ATTRIBUTE hssPrivTmpl[] = {
        { CKA_TOKEN,           &ckTrue,    sizeof(ckTrue)    },
        { CKA_HSS_LEVELS,      &levels,    sizeof(levels)    },
        { CKA_HSS_LMS_TYPES,   &lmsType,   sizeof(lmsType)   },
        { CKA_HSS_LMOTS_TYPES, &lmotsType, sizeof(lmotsType) },
    };

    printf("  XMSS key moved where an HSS key is added...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = create_data_object(session, &data);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    /* With storage off the destroy is not stored, so the next pass stores
     * the move and the HSS key at the key's old id together. */
    if (ret == CKR_OK) {
        setenv("WOLFPKCS11_NO_STORE", "1", 1);
        ret = funcList->C_DestroyObject(session, data);
        CHECK_CKR(ret, "destroy the oldest object, storage off");
        unsetenv("WOLFPKCS11_NO_STORE");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, &mech, hssPubTmpl,
            sizeof(hssPubTmpl) / sizeof(*hssPubTmpl), hssPrivTmpl,
            sizeof(hssPrivTmpl) / sizeof(*hssPrivTmpl), &hssPub, &hssPriv);
        CHECK_CKR(ret, "HSS keygen");
    }
    if (ret == CKR_OK)
        ret = expect_live_records(1, "after the move");
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_OK, "sign after the move");
    close_session(session);
    pkcs11_final();
    return ret;
}
#endif

/* Every signature of a key, then CKR_KEY_EXHAUSTED, also after a reload. */
static CK_RV test_exhaustion(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-exhaust";
    CK_ULONG i;
    CK_ULONG v = 1;

    printf("  XMSS key exhausts after %lu signatures...\n",
        XMSS_SHA2_10_256_SIGS);
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
    for (i = 0; ret == CKR_OK && i < XMSS_SHA2_10_256_SIGS; i++)
        ret = sign_expect(session, priv, CKR_OK, "sign");
    if (ret == CKR_OK)
        ret = sign_expect(session, priv, CKR_KEY_EXHAUSTED, "sign when spent");
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &v);
    if (ret == CKR_OK && v != 0) {
        fprintf(stderr, "\nspent key reports %lu keys remaining - FAIL\n", v);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    session = CK_INVALID_HANDLE;

    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK) {
        ret = sign_expect(session, priv, CKR_KEY_EXHAUSTED,
            "sign when spent, after reload");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Sign count times with the key in its own load of the token, writing each
 * index to fd when fd is not -1 and to idx when idx is not NULL. */
static CK_RV sign_indices(const XmssScheme* s, CK_BYTE* id, CK_ULONG idLen,
    int count, int fd, unsigned long* idx)
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
        ret = xmss_sign(session, s, priv, &sig, &sigLen);
        if (ret == CKR_OK) {
            q = sig_index(s, sig);
            if (fd >= 0 && write(fd, &q, sizeof(q)) != (ssize_t)sizeof(q))
                ret = CKR_GENERAL_ERROR;
            if (idx != NULL)
                idx[i] = q;
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Two processes signing with one key never share an index. */
static CK_RV test_two_process_signing(const XmssScheme* s)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "xmss-two-proc";
    enum { PER_PROC = 12 };
    unsigned long idx[2 * PER_PROC];
    CK_ULONG left = 0;
    int fds[2];
    pid_t pid;
    int status = 0;
    int i, j;

    printf("  %s: two processes signing with one key...\n", s->name);
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_key(session, s, id, sizeof(id) - 1, &pub, &priv);
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
        _exit(sign_indices(s, id, sizeof(id) - 1, PER_PROC, fds[1], NULL) ==
            CKR_OK ? 0 : 1);
    }
    close(fds[1]);
    if (pid < 0) {
        close(fds[0]);
        return CKR_GENERAL_ERROR;
    }
    ret = sign_indices(s, id, sizeof(id) - 1, PER_PROC, -1, idx);
    for (i = 0; i < PER_PROC; i++) {
        if (read(fds[0], &idx[PER_PROC + i], sizeof(idx[0])) !=
                (ssize_t)sizeof(idx[0])) {
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
            if (idx[i] == idx[j]) {
                fprintf(stderr, "\n%s index %lu used twice - FAIL\n",
                    s->name, idx[i]);
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
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &left);
    if (ret == CKR_OK && left != s->sigs - 2 * PER_PROC) {
        fprintf(stderr, "\n%s: %lu left after %d signatures - FAIL\n",
            s->name, (unsigned long)left, 2 * PER_PROC);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

#ifdef XMSS_TEST_THREADS
#define MT_THREADS 4
#define MT_SIGS    32
#define MT_READS   64

typedef struct MtCtx {
    CK_OBJECT_HANDLE pub;
    CK_OBJECT_HANDLE priv;
    CK_ULONG sigLen;
    unsigned long idx[MT_SIGS];
    CK_RV err;
} MtCtx;

/* A length query in a session of its own, which closing ends. */
static CK_RV sig_len_query(CK_OBJECT_HANDLE priv, CK_ULONG* len)
{
    CK_RV ret;
    CK_SESSION_HANDLE query = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_XMSS, NULL, 0 };

    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
        NULL, NULL, &query);
    if (ret == CKR_OK)
        ret = funcList->C_SignInit(query, &mech, priv);
    if (ret == CKR_OK) {
        *len = 0;
        ret = funcList->C_Sign(query, (CK_BYTE*)testMsg, TEST_MSG_LEN, NULL,
            len);
    }
    if (query != CK_INVALID_HANDLE)
        funcList->C_CloseSession(query);
    return ret;
}

static void* mt_signer(void* arg)
{
    MtCtx* c = (MtCtx*)arg;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_BYTE* sig;
    CK_ULONG sigLen = 0;
    CK_RV ret;
    int i;

    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
        NULL, NULL, &session);
    for (i = 0; ret == CKR_OK && i < MT_SIGS; i++) {
        sig = NULL;
        ret = xmss_sign(session, &xmss, c->priv, &sig, &sigLen);
        if (ret == CKR_OK) {
            ret = xmss_verify_msg(session, &xmss, c->pub, testMsg,
                TEST_MSG_LEN, sig, sigLen);
        }
        if (ret == CKR_OK)
            c->idx[i] = sig_index(&xmss, sig);
        if (sig != NULL)
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    c->err = ret;
    return NULL;
}

/* Keys remaining never goes up, and the other reads stay the same. */
static void* mt_reader(void* arg)
{
    MtCtx* c = (MtCtx*)arg;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_ULONG last = (CK_ULONG)-1;
    CK_ULONG cur = 0, len = 0;
    CK_RV ret;
    int i;

    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
        NULL, NULL, &session);
    for (i = 0; ret == CKR_OK && i < MT_READS; i++) {
        ret = get_ulong(session, c->priv, CKA_KEYS_REMAINING, &cur);
        if (ret == CKR_OK && cur > last)
            ret = CKR_GENERAL_ERROR;
        last = cur;
        if (ret == CKR_OK)
            ret = get_ulong(session, c->priv, CKA_PARAMETER_SET, &cur);
        if (ret == CKR_OK && cur != XMSS_SHA2_10_256)
            ret = CKR_GENERAL_ERROR;
        if (ret == CKR_OK)
            ret = sig_len_query(c->priv, &len);
        if (ret == CKR_OK && len != c->sigLen)
            ret = CKR_GENERAL_ERROR;
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    c->err = ret;
    return NULL;
}

static int cmp_index(const void* a, const void* b)
{
    unsigned long x = *(const unsigned long*)a;
    unsigned long y = *(const unsigned long*)b;

    return (x > y) - (x < y);
}

/* Threads sign with one key while another reads its attributes. */
static CK_RV test_concurrent_sign(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "xmss-threads";
    MtCtx ctx[MT_THREADS + 1];
    pthread_t tid[MT_THREADS + 1];
    int started[MT_THREADS + 1];
    unsigned long seen[MT_THREADS * MT_SIGS];
    CK_ULONG before = 0, after = 0, sigLen = 0;
    int i, j, n = 0;

    printf("  XMSS signing from %d threads with a reader...\n", MT_THREADS);
    XMEMSET(ctx, 0, sizeof(ctx));
    XMEMSET(started, 0, sizeof(started));
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_key(session, &xmss, id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &before);
    if (ret == CKR_OK) {
        ret = sig_len_query(priv, &sigLen);
        CHECK_CKR(ret, "signature length");
    }
    for (i = 0; ret == CKR_OK && i <= MT_THREADS; i++) {
        ctx[i].pub = pub;
        ctx[i].priv = priv;
        ctx[i].sigLen = sigLen;
        if (pthread_create(&tid[i], NULL,
                (i == MT_THREADS) ? mt_reader : mt_signer, &ctx[i]) != 0)
            ret = CKR_GENERAL_ERROR;
        else
            started[i] = 1;
    }
    for (i = 0; i <= MT_THREADS; i++) {
        if (started[i])
            pthread_join(tid[i], NULL);
        if (ret == CKR_OK && ctx[i].err != CKR_OK) {
            fprintf(stderr, "\nthread %d: %lx - FAIL\n", i,
                (unsigned long)ctx[i].err);
            ret = ctx[i].err;
        }
    }
    for (i = 0; ret == CKR_OK && i < MT_THREADS; i++) {
        for (j = 0; j < MT_SIGS; j++)
            seen[n++] = ctx[i].idx[j];
    }
    if (ret == CKR_OK) {
        qsort(seen, (size_t)n, sizeof(*seen), cmp_index);
        for (i = 0; i < n && ret == CKR_OK; i++) {
            if (seen[i] != (unsigned long)i) {
                fprintf(stderr, "\nindex %lu at position %d - FAIL\n",
                    seen[i], i);
                ret = CKR_GENERAL_ERROR;
            }
        }
    }
    if (ret == CKR_OK)
        ret = get_ulong(session, priv, CKA_KEYS_REMAINING, &after);
    if (ret == CKR_OK && after != before - (CK_ULONG)n) {
        fprintf(stderr, "\nkeys remaining %lu -> %lu after %d - FAIL\n",
            before, after, n);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}
#endif /* XMSS_TEST_THREADS */

static CK_RV run_all(void)
{
    CK_RV ret;

    ret = test_keygen_sign_verify(&xmss);
    if (ret == CKR_OK)
        ret = test_keygen_sign_verify(&xmssmt);
    if (ret == CKR_OK)
        ret = test_reload_no_reuse(&xmss);
    if (ret == CKR_OK)
        ret = test_reload_no_reuse(&xmssmt);
    if (ret == CKR_OK)
        ret = test_reload_no_reuse(&xmss192);
    if (ret == CKR_OK)
        ret = test_reload_no_reuse(&xmss512);
    if (ret == CKR_OK)
        ret = test_empty_message();
    if (ret == CKR_OK)
        ret = test_keygen_negative();
    if (ret == CKR_OK)
        ret = test_import_copy_refused();
    if (ret == CKR_OK)
        ret = test_rollback_refused();
    if (ret == CKR_OK)
        ret = test_set_pin_reseals();
    if (ret == CKR_OK)
        ret = test_write_failure_recovers();
    if (ret == CKR_OK)
        ret = test_logout_login();
    if (ret == CKR_OK)
        ret = test_set_pin_same_session();
    if (ret == CKR_OK)
        ret = test_keys_remaining_logged_out();
    if (ret == CKR_OK)
        ret = test_key_class_and_single_part();
#ifdef XMSS_TEST_THREADS
    if (ret == CKR_OK)
        ret = test_concurrent_sign();
#endif
    if (ret == CKR_OK)
        ret = test_two_process_signing(&xmss);
    if (ret == CKR_OK)
        ret = test_two_process_signing(&xmssmt);
    if (ret == CKR_OK)
        ret = test_destroy_removes_record();
    if (ret == CKR_OK)
        ret = test_move_keeps_state();
    if (ret == CKR_OK)
        ret = test_policy_change();
    if (ret == CKR_OK)
        ret = test_mt_attributes_after_reload();
#ifdef WOLFPKCS11_LMS_PRIVATE
    if (ret == CKR_OK)
        ret = test_mixed_token();
    if (ret == CKR_OK)
        ret = test_mixed_move();
#endif
    if (ret == CKR_OK)
        ret = test_exhaustion();
    return ret;
}

int main(void)
{
    CK_RV ret;

    XSETENV("WOLFPKCS11_TOKEN_PATH", storeDir, 1);
    printf("wolfPKCS11 XMSS private-key (sign) test\n");
    ret = run_all();
    cleanup_store();
    if (ret != CKR_OK) {
        printf("\nTest failed with error: %lx\n", (unsigned long)ret);
        return 1;
    }
    printf("\nAll tests passed!\n");
    return 0;
}

#else

int main(void)
{
    printf("XMSS sign support (--enable-xmss-private) not compiled in!\n");
    return 77;
}

#endif
