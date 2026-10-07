/* unwrap_keygen_test.c
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
 * Contract checks for C_UnwrapKey, key and key-pair generation, and key
 * encapsulation.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <limits.h>

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
    #define KEYPAIR_PERSIST_TEST
    #include <unistd.h>
    #include <sys/wait.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#if defined(WOLFPKCS11_KEYPAIR_GEN_COMMON_LABEL) && defined(HAVE_ECC) && \
    defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
    #define LABEL_ALLOC_FAIL_TEST
    #include <stdlib.h>
    #include <wolfssl/wolfcrypt/memory.h>
#endif

#define TEST_DIR "./store/unwrap_keygen_test"

/* CK_ULONG lengths above the 32-bit range can only be expressed on LP64. */
#if ULONG_MAX > 0xFFFFFFFFUL
    #define WIDE_CK_ULONG
    #define LEN_ABOVE_WORD32(n) ((CK_ULONG)0xFFFFFFFFUL + 1 + (CK_ULONG)(n))
#endif

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    #define AES_UNWRAP_TEST
#endif

#ifdef AES_UNWRAP_TEST
static CK_KEY_TYPE aesType = CKK_AES;

static CK_RV create_aes_unwrap_key(CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass,         sizeof(secretClass)  },
        { CKA_KEY_TYPE, &aesType,             sizeof(aesType)      },
        { CKA_VALUE,    (void*)aes_cbc_key,   sizeof(aes_cbc_key)  },
        { CKA_ENCRYPT,  &ckTrue,              sizeof(ckTrue)       },
        { CKA_UNWRAP,   &ckTrue,              sizeof(ckTrue)       },
        { CKA_PRIVATE,  &ckFalse,             sizeof(ckFalse)      },
    };

    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), key);
}
#endif

#ifndef NO_RSA
static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
static CK_KEY_TYPE rsaType = CKK_RSA;

static CK_RV create_rsa_unwrap_keys(CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE* pub,
                                    CK_OBJECT_HANDLE* priv)
{
    CK_RV rv;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,           &pubClass,        sizeof(pubClass)         },
        { CKA_KEY_TYPE,        &rsaType,         sizeof(rsaType)          },
        { CKA_ENCRYPT,         &ckTrue,          sizeof(ckTrue)           },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,            &privClass,        sizeof(privClass)         },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_UNWRAP,           &ckTrue,           sizeof(ckTrue)            },
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

    rv = funcList->C_CreateObject(session, pubTmpl,
                                  sizeof(pubTmpl) / sizeof(*pubTmpl), pub);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, privTmpl,
                                      sizeof(privTmpl) / sizeof(*privTmpl),
                                      priv);
    }
    return rv;
}

#ifdef WIDE_CK_ULONG
/* RSA PKCS#1 v1.5 encrypt a 16-byte secret to make a valid wrapped key. */
static CK_RV rsa_wrap_secret(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub,
                             byte* out, CK_ULONG* outLen)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    byte secret[16];

    XMEMSET(secret, 0x5a, sizeof(secret));
    rv = funcList->C_EncryptInit(session, &mech, pub);
    if (rv == CKR_OK) {
        rv = funcList->C_Encrypt(session, secret, sizeof(secret), out, outLen);
    }
    return rv;
}
#endif /* WIDE_CK_ULONG */
#endif

#ifdef WIDE_CK_ULONG
static void test_unwrap_wrapped_len_beyond_word32(CK_SESSION_HANDLE session)
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
#ifdef AES_UNWRAP_TEST
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_MECHANISM aesMech = { CKM_AES_CBC_PAD, (void*)aes_cbc_iv,
                             sizeof(aes_cbc_iv) };
    byte aesWrapped[32];
#endif
#ifndef NO_RSA
    CK_OBJECT_HANDLE rsaPub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsaPriv = CK_INVALID_HANDLE;
    CK_MECHANISM rsaMech = { CKM_RSA_PKCS, NULL, 0 };
    byte rsaWrapped[256];
    CK_ULONG rsaWrappedLen = sizeof(rsaWrapped);
#endif

#ifdef AES_UNWRAP_TEST
    XMEMSET(aesWrapped, 0, sizeof(aesWrapped));
    rv = create_aes_unwrap_key(session, &aesKey);
    CHECK_RV(rv, "create AES unwrapping key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &aesMech, aesKey, aesWrapped,
                 LEN_ABOVE_WORD32(sizeof(aesWrapped)), tmpl, tmplCnt, &key);
        CHECK_RV(rv, "AES unwrap with wrapped length beyond 32 bits",
                 CKR_WRAPPED_KEY_LEN_RANGE);
        if (rv == CKR_OK) {
            funcList->C_DestroyObject(session, key);
        }
        key = CK_INVALID_HANDLE;
    }
#endif

#ifndef NO_RSA
    rv = create_rsa_unwrap_keys(session, &rsaPub, &rsaPriv);
    CHECK_RV(rv, "create RSA unwrapping keys", CKR_OK);
    if (rv == CKR_OK) {
        rv = rsa_wrap_secret(session, rsaPub, rsaWrapped, &rsaWrappedLen);
        CHECK_RV(rv, "RSA wrap secret", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &rsaMech, rsaPriv, rsaWrapped,
                 LEN_ABOVE_WORD32(rsaWrappedLen), tmpl, tmplCnt, &key);
        CHECK_RV(rv, "RSA unwrap with wrapped length beyond 32 bits",
                 CKR_WRAPPED_KEY_LEN_RANGE);
        if (rv == CKR_OK) {
            funcList->C_DestroyObject(session, key);
        }
        key = CK_INVALID_HANDLE;

        rv = funcList->C_UnwrapKey(session, &rsaMech, rsaPriv, rsaWrapped,
                 rsaWrappedLen, tmpl, tmplCnt, &key);
        CHECK_RV(rv, "RSA unwrap with exact wrapped length", CKR_OK);
        if (rv == CKR_OK) {
            funcList->C_DestroyObject(session, key);
        }
    }
#endif
    (void)session;
    (void)rv;
    (void)key;
    (void)tmplCnt;
}
#endif /* WIDE_CK_ULONG */

static void test_unwrap_failure_codes(CK_SESSION_HANDLE session)
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
#ifdef AES_UNWRAP_TEST
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_MECHANISM cbcMech = { CKM_AES_CBC, (void*)aes_cbc_iv,
                             sizeof(aes_cbc_iv) };
    CK_MECHANISM padMech = { CKM_AES_CBC_PAD, (void*)aes_cbc_iv,
                             sizeof(aes_cbc_iv) };
    byte plain[16];
    byte badPad[16];
    CK_ULONG badPadLen = sizeof(badPad);
#endif
#ifndef NO_RSA
    CK_OBJECT_HANDLE rsaPub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsaPriv = CK_INVALID_HANDLE;
    CK_MECHANISM rsaMech = { CKM_RSA_PKCS, NULL, 0 };
    byte rsaBlob[256];
#endif

#ifdef AES_UNWRAP_TEST
    /* A zero final block decrypts to an invalid CBC pad byte. */
    XMEMSET(plain, 0, sizeof(plain));
    rv = create_aes_unwrap_key(session, &aesKey);
    CHECK_RV(rv, "create AES unwrapping key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_EncryptInit(session, &cbcMech, aesKey);
        CHECK_RV(rv, "AES-CBC encrypt init", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Encrypt(session, plain, sizeof(plain), badPad,
                                 &badPadLen);
        CHECK_RV(rv, "AES-CBC encrypt", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &padMech, aesKey, badPad,
                                   badPadLen, tmpl, tmplCnt, &key);
        CHECK_RV(rv, "AES-CBC-PAD unwrap with bad padding",
                 CKR_WRAPPED_KEY_INVALID);
        rv = funcList->C_UnwrapKey(session, &padMech, aesKey, badPad,
                                   badPadLen - 1, tmpl, tmplCnt, &key);
        CHECK_RV(rv, "AES-CBC-PAD unwrap with partial block",
                 CKR_WRAPPED_KEY_LEN_RANGE);
    }
#endif

#ifndef NO_RSA
    rv = create_rsa_unwrap_keys(session, &rsaPub, &rsaPriv);
    CHECK_RV(rv, "create RSA unwrapping keys", CKR_OK);
    if (rv == CKR_OK) {
        XMEMSET(rsaBlob, 0x5a, sizeof(rsaBlob));
        rv = funcList->C_UnwrapKey(session, &rsaMech, rsaPriv, rsaBlob,
                                   sizeof(rsaBlob), tmpl, tmplCnt, &key);
        CHECK_RV(rv, "RSA unwrap with bad PKCS#1 padding",
                 CKR_WRAPPED_KEY_INVALID);
        rv = funcList->C_UnwrapKey(session, &rsaMech, rsaPriv, rsaBlob,
                                   sizeof(rsaBlob) / 2, tmpl, tmplCnt, &key);
        CHECK_RV(rv, "RSA unwrap with short wrapped key",
                 CKR_WRAPPED_KEY_LEN_RANGE);
    }
#endif
    (void)session;
    (void)rv;
    (void)key;
    (void)tmplCnt;
}

#ifdef KEYPAIR_PERSIST_TEST
static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";

static CK_RV token_init(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE soSession = 0;
    unsigned char label[32];

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv != CKR_OK)
        return rv;
    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_OK && slotCount == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK) {
        *slot = slotList[0];
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, "unwrap-keygen", 13);
        rv = funcList->C_InitToken(*slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(*slot,
                 CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &soSession);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(soSession, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
        if (rv == CKR_OK) {
            rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                     (CK_ULONG)XSTRLEN(userPin));
            funcList->C_Logout(soSession);
        }
        funcList->C_CloseSession(soSession);
    }
    funcList->C_Finalize(NULL);
    return rv;
}

static CK_RV user_session(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                 CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(*session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    return rv;
}

/* The stored private key must carry its initial-state flags even when the
 * process ends right after key-pair generation returns. */
static void test_keypair_initial_states_stored(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ULONG found = 0;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
    char label[] = "stored-initial-states";
    CK_BBOOL alwaysSensitive = CK_FALSE;
    CK_BBOOL neverExtractable = CK_FALSE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_TOKEN,     &ckTrue,         sizeof(ckTrue)          },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,       &ckTrue,  sizeof(ckTrue)    },
        { CKA_SENSITIVE,   &ckTrue,  sizeof(ckTrue)    },
        { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)   },
        { CKA_LABEL,       label,    sizeof(label) - 1 },
    };
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &privKeyClass, sizeof(privKeyClass) },
        { CKA_LABEL, label,         sizeof(label) - 1    },
    };
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_ALWAYS_SENSITIVE,  &alwaysSensitive,  sizeof(CK_BBOOL) },
        { CKA_NEVER_EXTRACTABLE, &neverExtractable, sizeof(CK_BBOOL) },
    };
    pid_t pid;
    int status = 0;

    rv = token_init(&slot);
    CHECK_RV(rv, "initialize token", CKR_OK);
    if (rv != CKR_OK)
        return;

    pid = fork();
    if (pid == 0) {
        rv = user_session(slot, &session);
        if (rv == CKR_OK) {
            rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
                     sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
                     sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
        }
        /* End without C_Finalize so only what was stored survives. */
        _exit(rv == CKR_OK ? 0 : 1);
    }
    CHECK_TRUE(pid > 0, "fork key-pair generator");
    if (pid <= 0)
        return;
    CHECK_TRUE(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0, "generate token key pair");

    rv = user_session(slot, &session);
    CHECK_RV(rv, "reopen token", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjectsInit(session, findTmpl,
                 sizeof(findTmpl) / sizeof(*findTmpl));
        if (rv == CKR_OK) {
            rv = funcList->C_FindObjects(session, &priv, 1, &found);
            funcList->C_FindObjectsFinal(session);
        }
        CHECK_TRUE(rv == CKR_OK && found == 1, "find stored private key");
    }
    if (rv == CKR_OK && found == 1) {
        rv = funcList->C_GetAttributeValue(session, priv, getTmpl,
                 sizeof(getTmpl) / sizeof(*getTmpl));
        CHECK_RV(rv, "read stored initial states", CKR_OK);
        CHECK_TRUE(alwaysSensitive == CK_TRUE,
                   "stored private key is always sensitive");
        CHECK_TRUE(neverExtractable == CK_TRUE,
                   "stored private key is never extractable");
        funcList->C_DestroyObject(session, priv);
    }
    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    funcList->C_Finalize(NULL);
    (void)pub;
}
#endif /* KEYPAIR_PERSIST_TEST */

#ifdef LABEL_ALLOC_FAIL_TEST
/* Fails the allocation of failSz bytes after failSkip such allocations. */
static size_t failSz = 0;
static int failSkip = 0;

static void* fail_malloc(size_t n)
{
    if (failSz != 0 && n == failSz) {
        if (failSkip == 0) {
            failSz = 0;
            return NULL;
        }
        failSkip--;
    }
    return malloc(n);
}

static void fail_free(void* p)
{
    free(p);
}

static void* fail_realloc(void* p, size_t n)
{
    return realloc(p, n);
}

/* Key-pair generation must fail when the common label cannot be copied to
 * the public key. */
static void test_keypair_common_label_copy_failure(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    char label[] = "common-label-0123456789abcdef-0123456789abcdef-0123456789";
    byte got[sizeof(label)];
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_PRIVATE, &ckFalse, sizeof(ckFalse)   },
        { CKA_LABEL,   label,    sizeof(label) - 1 },
    };
    CK_ATTRIBUTE getLabel[] = {
        { CKA_LABEL, got, sizeof(got) },
    };

    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
             sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
             sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
    CHECK_RV(rv, "generate key pair with common label", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_GetAttributeValue(session, pub, getLabel, 1);
        CHECK_TRUE(rv == CKR_OK && getLabel[0].ulValueLen == sizeof(label) - 1
                   && XMEMCMP(got, label, sizeof(label) - 1) == 0,
                   "public key takes the private key label");
        funcList->C_DestroyObject(session, pub);
        funcList->C_DestroyObject(session, priv);
    }

    pub = CK_INVALID_HANDLE;
    priv = CK_INVALID_HANDLE;
    /* The private key's own label copy comes first; fail the next one. */
    failSz = sizeof(label) - 1;
    failSkip = 1;
    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
             sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
             sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
    CHECK_TRUE(failSz == 0, "label allocation failure injected");
    failSz = 0;
    CHECK_RV(rv, "key pair with failed common label copy", CKR_DEVICE_MEMORY);
    CHECK_TRUE(pub == CK_INVALID_HANDLE && priv == CK_INVALID_HANDLE,
               "failed common label copy returns no key handles");
    if (rv == CKR_OK) {
        funcList->C_DestroyObject(session, pub);
        funcList->C_DestroyObject(session, priv);
    }
}
#endif /* LABEL_ALLOC_FAIL_TEST */

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv == CKR_OK) {
#ifdef WIDE_CK_ULONG
        test_unwrap_wrapped_len_beyond_word32(session);
#endif
        test_unwrap_failure_codes(session);
#ifdef LABEL_ALLOC_FAIL_TEST
        test_keypair_common_label_copy_failure(session);
#endif
        funcList->C_CloseSession(session);
    }
    funcList->C_Finalize(NULL);

#ifdef KEYPAIR_PERSIST_TEST
    test_keypair_initial_states_stored();
#endif

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

    printf("=== wolfPKCS11 unwrap and key generation contract test ===\n");
#ifdef LABEL_ALLOC_FAIL_TEST
    if (wolfSSL_SetAllocators(fail_malloc, fail_free, fail_realloc) != 0) {
        fprintf(stderr, "FAIL: wolfSSL_SetAllocators\n");
        return 1;
    }
#endif
    run_test();
    return pkcs11_test_summary();
}
