/* derive_template_rollback_test.c
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
 * Tests C_DeriveKey templates weaker than the base key, the DH secret length
 * and the TLS 1.2 key-and-MAC derive leaving no keys behind on failure.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"

#define TEST_DIR "./store/derive_template_rollback_test"

#if defined(WOLFSSL_HAVE_PRF) && !defined(WOLFPKCS11_NSS) && \
    !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_CUSTOM_STORE) && \
    !defined(WOLFPKCS11_TPM_STORE) && !defined(WOLFPKCS11_NO_ENV) && \
    !defined(_WIN32)
    #define TEST_TOKEN_RELOAD
    #include <dirent.h>
    #include <errno.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #define SNAP_DIR TEST_DIR "-snap"
#endif

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

static void check(int cond, const char* msg)
{
    if (cond) {
        printf("PASS: %s\n", msg);
        test_passed++;
    }
    else {
        fprintf(stderr, "FAIL: %s\n", msg);
        test_failed++;
    }
}

static void check_rv(CK_RV rv, CK_RV exp, const char* msg)
{
    if (rv != exp)
        fprintf(stderr, "  got 0x%lx, expected 0x%lx\n", (unsigned long)rv,
                (unsigned long)exp);
    check(rv == exp, msg);
}

#if (defined(HAVE_ECC) && !defined(WOLFPKCS11_LEGACY_DERIVE_NO_INHERIT) && \
     !defined(WOLFPKCS11_NSS)) || !defined(NO_DH) || defined(WOLFSSL_HAVE_PRF)
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static void destroy_obj(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* obj)
{
    if (*obj != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, *obj);
        *obj = CK_INVALID_HANDLE;
    }
}
#endif

#if defined(HAVE_ECC) && !defined(WOLFPKCS11_LEGACY_DERIVE_NO_INHERIT) && \
    !defined(WOLFPKCS11_NSS)
static CK_RV read_bool(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                       CK_ATTRIBUTE_TYPE type, CK_BBOOL* out)
{
    CK_ATTRIBUTE attr = { type, out, sizeof(*out) };

    return funcList->C_GetAttributeValue(session, obj, &attr, 1);
}

static CK_RV ecdh_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                         CK_BBOOL* sensitive, CK_BBOOL* extractable,
                         CK_OBJECT_HANDLE* key)
{
    CK_ULONG len = 32;
    CK_ECDH1_DERIVE_PARAMS params;
    CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    CK_ATTRIBUTE tmpl[4] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
    };
    CK_ULONG cnt = 3;

    XMEMSET(&params, 0, sizeof(params));
    params.kdf = CKD_NULL;
    params.pPublicData = ecc_p256_point;
    params.ulPublicDataLen = sizeof(ecc_p256_point);
    if (sensitive != NULL) {
        tmpl[cnt].type = CKA_SENSITIVE;
        tmpl[cnt].pValue = sensitive;
        tmpl[cnt++].ulValueLen = sizeof(CK_BBOOL);
    }
    else if (extractable != NULL) {
        tmpl[cnt].type = CKA_EXTRACTABLE;
        tmpl[cnt].pValue = extractable;
        tmpl[cnt++].ulValueLen = sizeof(CK_BBOOL);
    }
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl, cnt, key);
}

static void test_ecdh_weaker_template(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE plain = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_BBOOL val = 0xAA;
    CK_BBOOL baseVal = 0x55;
    CK_BBOOL sensitive = CK_TRUE;
    CK_BBOOL extractable = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &privClass,      sizeof(privClass)       },
        { CKA_KEY_TYPE,    &ecType,         sizeof(ecType)          },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS,   ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,       ecc_p256_priv,   sizeof(ecc_p256_priv)   },
        { CKA_SENSITIVE,   &sensitive,      sizeof(sensitive)       },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)     },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    printf("\n--- ECDH derive templates against base protection ---\n");
    rv = funcList->C_CreateObject(session, tmpl, cnt, &base);
    check_rv(rv, CKR_OK, "create protected EC private key");
    if (rv == CKR_OK) {
        sensitive = CK_FALSE;
        extractable = CK_TRUE;
        rv = funcList->C_CreateObject(session, tmpl, cnt, &plain);
        check_rv(rv, CKR_OK, "create plain EC private key");
    }
    if (rv != CKR_OK)
        goto cleanup;

    rv = ecdh_derive(session, base, &ckFalse, NULL, &key);
    check_rv(rv, CKR_TEMPLATE_INCONSISTENT,
             "CKA_SENSITIVE=FALSE under a sensitive base refused");
    check(key == CK_INVALID_HANDLE, "no key from the refused template");
    destroy_obj(session, &key);

    rv = ecdh_derive(session, base, NULL, &ckTrue, &key);
    check_rv(rv, CKR_TEMPLATE_INCONSISTENT,
             "CKA_EXTRACTABLE=TRUE under a non-extractable base refused");
    check(key == CK_INVALID_HANDLE, "no key from the refused template");
    destroy_obj(session, &key);

    rv = ecdh_derive(session, base, NULL, NULL, &key);
    check_rv(rv, CKR_OK, "derive with protection left out");
    if (rv == CKR_OK) {
        rv = read_bool(session, key, CKA_SENSITIVE, &val);
        check(rv == CKR_OK && val == CK_TRUE,
              "omitted CKA_SENSITIVE inherited");
        rv = read_bool(session, key, CKA_EXTRACTABLE, &val);
        check(rv == CKR_OK && val == CK_FALSE,
              "omitted CKA_EXTRACTABLE inherited");
        rv = read_bool(session, base, CKA_ALWAYS_SENSITIVE, &baseVal);
        if (rv == CKR_OK)
            rv = read_bool(session, key, CKA_ALWAYS_SENSITIVE, &val);
        check(rv == CKR_OK && val == baseVal,
              "CKA_ALWAYS_SENSITIVE follows the protected base");
    }
    destroy_obj(session, &key);

    rv = ecdh_derive(session, base, &ckTrue, NULL, &key);
    check_rv(rv, CKR_OK, "CKA_SENSITIVE=TRUE under a sensitive base allowed");
    destroy_obj(session, &key);

    rv = ecdh_derive(session, plain, &ckTrue, NULL, &key);
    check_rv(rv, CKR_OK, "CKA_SENSITIVE=TRUE under a plain base allowed");
    if (rv == CKR_OK) {
        rv = read_bool(session, key, CKA_ALWAYS_SENSITIVE, &val);
        check(rv == CKR_OK && val == CK_FALSE,
              "CKA_ALWAYS_SENSITIVE follows the plain base");
    }
    destroy_obj(session, &key);

    rv = ecdh_derive(session, plain, &ckFalse, NULL, &key);
    check_rv(rv, CKR_OK, "CKA_SENSITIVE=FALSE under a plain base allowed");
    destroy_obj(session, &key);

cleanup:
    destroy_obj(session, &plain);
    destroy_obj(session, &base);
}
#endif

#ifndef NO_DH
/* With private value 1000 and peer value 2, the secret is 2^1000: 126 bytes
 * without its leading zeros, 256 as long as the prime. */
static void test_dh_secret_length(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE dhType = CKK_DH;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte priv[] = { 0x03, 0xE8 };
    byte peer[] = { 0x02 };
    byte value[sizeof(dh_ffdhe2048_p)];
    byte expected[sizeof(dh_ffdhe2048_p)];
    CK_ULONG valueLen = 0;
    CK_ULONG reqLen = sizeof(dh_ffdhe2048_p);
    CK_MECHANISM mech = { CKM_DH_PKCS_DERIVE, peer, sizeof(peer) };
    CK_ATTRIBUTE baseTmpl[] = {
        { CKA_CLASS,       &privClass,     sizeof(privClass)      },
        { CKA_KEY_TYPE,    &dhType,        sizeof(dhType)         },
        { CKA_PRIVATE,     &ckFalse,       sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,       sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,        sizeof(ckTrue)         },
        { CKA_DERIVE,      &ckTrue,        sizeof(ckTrue)         },
        { CKA_PRIME,       dh_ffdhe2048_p, sizeof(dh_ffdhe2048_p) },
        { CKA_BASE,        dh_ffdhe2048_g, sizeof(dh_ffdhe2048_g) },
        { CKA_VALUE,       priv,           sizeof(priv)           },
    };
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &reqLen,         sizeof(reqLen)         },
    };
    CK_ULONG keyCnt = sizeof(keyTmpl) / sizeof(*keyTmpl);
    CK_ATTRIBUTE get[] = {
        { CKA_VALUE,     value,     sizeof(value)    },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
    };

    printf("\n--- DH derive secret length ---\n");
    XMEMSET(expected, 0, sizeof(expected));
    expected[sizeof(expected) - 126] = 0x01;

    rv = funcList->C_CreateObject(session, baseTmpl,
                                  sizeof(baseTmpl) / sizeof(*baseTmpl), &base);
    check_rv(rv, CKR_OK, "create DH private key");
    if (rv != CKR_OK)
        return;

    rv = funcList->C_DeriveKey(session, &mech, base, keyTmpl, keyCnt - 1,
                               &key);
    check_rv(rv, CKR_OK, "DH derive without CKA_VALUE_LEN");
    if (rv == CKR_OK) {
        rv = funcList->C_GetAttributeValue(session, key, get, 2);
        check_rv(rv, CKR_OK, "read derived DH secret");
        check(rv == CKR_OK && valueLen == 126 && get[0].ulValueLen == 126 &&
              XMEMCMP(value, expected + sizeof(expected) - 126, 126) == 0,
              "DH secret without CKA_VALUE_LEN drops its leading zeros");
    }
    destroy_obj(session, &key);

    reqLen = 0;
    rv = funcList->C_DeriveKey(session, &mech, base, keyTmpl, keyCnt, &key);
    check_rv(rv, CKR_OK, "DH derive with a zero CKA_VALUE_LEN");
    if (rv == CKR_OK) {
        get[0].ulValueLen = sizeof(value);
        rv = funcList->C_GetAttributeValue(session, key, get, 1);
        check(rv == CKR_OK && get[0].ulValueLen == 126 &&
              XMEMCMP(value, expected + sizeof(expected) - 126, 126) == 0,
              "DH secret with a zero CKA_VALUE_LEN drops its leading zeros");
    }
    destroy_obj(session, &key);

    reqLen = sizeof(dh_ffdhe2048_p);
    rv = funcList->C_DeriveKey(session, &mech, base, keyTmpl, keyCnt, &key);
    check_rv(rv, CKR_OK, "DH derive with CKA_VALUE_LEN of the prime");
    if (rv == CKR_OK) {
        get[0].ulValueLen = sizeof(value);
        rv = funcList->C_GetAttributeValue(session, key, get, 1);
        check(rv == CKR_OK && get[0].ulValueLen == sizeof(expected) &&
              XMEMCMP(value, expected, sizeof(expected)) == 0,
              "DH secret of the prime length");
    }
    destroy_obj(session, &key);

    reqLen = sizeof(dh_ffdhe2048_p) + 1;
    rv = funcList->C_DeriveKey(session, &mech, base, keyTmpl, keyCnt, &key);
    check_rv(rv, CKR_ATTRIBUTE_VALUE_INVALID,
             "DH derive longer than the prime refused");
    destroy_obj(session, &key);

    destroy_obj(session, &base);
}

#endif

#ifdef WOLFSSL_HAVE_PRF
#define MAX_TEST_OBJECTS 8192

static CK_OBJECT_HANDLE fill[MAX_TEST_OBJECTS];

#define COUNT_FAILED ((CK_ULONG)-1)

/* Counts the secret keys, only the token ones when `token' is set. */
static CK_ULONG count_secret_keys(CK_SESSION_HANDLE session, int token)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_TOKEN, &ckTrue,         sizeof(ckTrue)         },
    };
    CK_OBJECT_HANDLE found[64];
    CK_ULONG cnt = 0;
    CK_ULONG total = 0;

    if (funcList->C_FindObjectsInit(session, tmpl, token ? 2 : 1) != CKR_OK)
        return COUNT_FAILED;
    do {
        if (funcList->C_FindObjects(session, found, 64, &cnt) != CKR_OK) {
            total = COUNT_FAILED;
            break;
        }
        total += cnt;
    } while (cnt == 64);
    funcList->C_FindObjectsFinal(session);
    return total;
}

static CK_RV tls12_key_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                              CK_KEY_TYPE keyType, CK_ULONG keyBits,
                              CK_BBOOL* token, CK_SSL3_KEY_MAT_OUT* out)
{
    CK_BYTE clientRandom[32];
    CK_BYTE serverRandom[32];
    CK_TLS12_KEY_MAT_PARAMS params;
    CK_MECHANISM mech = { CKM_TLS12_KEY_AND_MAC_DERIVE, &params,
                          sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &keyType,        sizeof(keyType)        },
        { CKA_TOKEN,       token,           sizeof(CK_BBOOL)       },
        { CKA_ENCRYPT,     &ckTrue,         sizeof(ckTrue)         },
    };

    XMEMSET(clientRandom, 0x11, sizeof(clientRandom));
    XMEMSET(serverRandom, 0x22, sizeof(serverRandom));
    XMEMSET(&params, 0, sizeof(params));
    params.ulMacSizeInBits = 256;
    params.ulKeySizeInBits = keyBits;
    params.ulIVSizeInBits = 0;
    params.bIsExport = CK_FALSE;
    params.RandomInfo.pClientRandom = clientRandom;
    params.RandomInfo.ulClientRandomLen = sizeof(clientRandom);
    params.RandomInfo.pServerRandom = serverRandom;
    params.RandomInfo.ulServerRandomLen = sizeof(serverRandom);
    params.pReturnedKeyMaterial = out;
    params.prfHashMechanism = CKM_SHA256;
    XMEMSET(out, 0, sizeof(*out));

    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), NULL);
}

static int no_handles(CK_SSL3_KEY_MAT_OUT* out)
{
    return out->hClientMacSecret == CK_INVALID_HANDLE &&
           out->hServerMacSecret == CK_INVALID_HANDLE &&
           out->hClientKey == CK_INVALID_HANDLE &&
           out->hServerKey == CK_INVALID_HANDLE;
}

static void destroy_key_mat(CK_SESSION_HANDLE session, CK_SSL3_KEY_MAT_OUT* out)
{
    destroy_obj(session, &out->hClientMacSecret);
    destroy_obj(session, &out->hServerMacSecret);
    destroy_obj(session, &out->hClientKey);
    destroy_obj(session, &out->hServerKey);
}

static void empty_objects(CK_SESSION_HANDLE session, CK_ULONG n)
{
    while (n > 0)
        destroy_obj(session, &fill[--n]);
}

/* Creates data objects until `room' are left before the session or token
 * limit. Returns the number created, 0 when no limit was reached. */
static CK_ULONG fill_objects(CK_SESSION_HANDLE session, CK_BBOOL* token,
                             CK_ULONG room)
{
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
        { CKA_TOKEN, token,      sizeof(CK_BBOOL)  },
    };
    CK_ULONG n = 0;

    while (n < MAX_TEST_OBJECTS && funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &fill[n]) == CKR_OK) {
        n++;
    }
    if (n == MAX_TEST_OBJECTS || n < room) {
        empty_objects(session, n);
        return 0;
    }
    while (room-- > 0)
        destroy_obj(session, &fill[--n]);
    return n;
}

static void test_tls12_rollback(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_SSL3_KEY_MAT_OUT out;
    CK_ULONG before;
    CK_ULONG n;
    byte master[48];
    CK_ATTRIBUTE baseTmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,       master,          sizeof(master)         },
    };

    printf("\n--- TLS 1.2 key and MAC derive rollback ---\n");
    XMEMSET(master, 0x33, sizeof(master));
    rv = funcList->C_CreateObject(session, baseTmpl,
                                  sizeof(baseTmpl) / sizeof(*baseTmpl), &base);
    check_rv(rv, CKR_OK, "create TLS master secret");
    if (rv != CKR_OK)
        return;

    rv = tls12_key_derive(session, base, CKK_GENERIC_SECRET, 128, &ckFalse,
                          &out);
    check_rv(rv, CKR_OK, "TLS 1.2 key and MAC derive");
    check(rv != CKR_OK || (out.hClientMacSecret != CK_INVALID_HANDLE &&
          out.hServerKey != CK_INVALID_HANDLE), "four keys returned");
    destroy_key_mat(session, &out);

#if !defined(WOLFPKCS11_NSS) && !defined(NO_AES)
    {
        /* Other sizes need another master, as the first is tied to the
         * sizes it derived. */
        CK_OBJECT_HANDLE aesBase = CK_INVALID_HANDLE;

        rv = funcList->C_CreateObject(session, baseTmpl,
                                      sizeof(baseTmpl) / sizeof(*baseTmpl),
                                      &aesBase);
        check_rv(rv, CKR_OK, "create TLS master secret for AES keys");
        before = count_secret_keys(session, 0);
        rv = tls12_key_derive(session, aesBase, CKK_AES, 160, &ckFalse, &out);
        check(rv != CKR_OK && rv != CKR_KEY_FUNCTION_NOT_PERMITTED,
              "TLS 1.2 derive with a bad client key fails");
        check(no_handles(&out),
              "no handles returned after a client key failure");
        check(before != COUNT_FAILED &&
              count_secret_keys(session, 0) == before,
              "no keys left after a client key failure");
        destroy_key_mat(session, &out);
        destroy_obj(session, &aesBase);
    }
#endif

    /* Leave room for three keys so the server key fails to be added. */
    n = fill_objects(session, &ckFalse, 3);
    if (n == 0) {
        printf("SKIP: object limit not reached\n");
    }
    else {
        before = count_secret_keys(session, 0);
        rv = tls12_key_derive(session, base, CKK_GENERIC_SECRET, 128,
                              &ckFalse, &out);
        check(rv != CKR_OK, "TLS 1.2 derive past the object limit fails");
        check(no_handles(&out), "no handles returned past the object limit");
        check(before != COUNT_FAILED &&
              count_secret_keys(session, 0) == before,
              "keys removed after a failed add");
        destroy_key_mat(session, &out);
        empty_objects(session, n);
    }

    destroy_obj(session, &base);
}

#ifdef TEST_TOKEN_RELOAD
/* Replaces the files in `to' with copies of those in `from'. */
static int copy_dir(const char* from, const char* to)
{
    DIR* d;
    struct dirent* e;
    char src[256];
    char dst[256];
    byte buf[4096];
    size_t len;
    FILE* in;
    FILE* out;
    int ret = 0;

    if (mkdir(to, 0700) != 0 && errno != EEXIST)
        return -1;
    d = opendir(to);
    if (d == NULL)
        return -1;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] != '.' &&
                snprintf(dst, sizeof(dst), "%s/%s", to, e->d_name) <
                (int)sizeof(dst)) {
            (void)unlink(dst);
        }
    }
    closedir(d);

    d = opendir(from);
    if (d == NULL)
        return -1;
    while (ret == 0 && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        if (snprintf(src, sizeof(src), "%s/%s", from, e->d_name) >=
                (int)sizeof(src) ||
                snprintf(dst, sizeof(dst), "%s/%s", to, e->d_name) >=
                (int)sizeof(dst)) {
            ret = -1;
            break;
        }
        in = fopen(src, "rb");
        out = (in != NULL) ? fopen(dst, "wb") : NULL;
        if (out == NULL)
            ret = -1;
        while (ret == 0 && (len = fread(buf, 1, sizeof(buf), in)) > 0) {
            if (fwrite(buf, 1, len, out) != len)
                ret = -1;
        }
        if (in != NULL)
            fclose(in);
        if (out != NULL && fclose(out) != 0)
            ret = -1;
    }
    closedir(d);
    return ret;
}

/* Token MAC keys removed after the client key fails to be added are gone
 * from the store the failed derive left behind. */
static void test_tls12_token_rollback(CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_SSL3_KEY_MAT_OUT out;
    CK_ULONG before;
    CK_ULONG n;
    CK_C_INITIALIZE_ARGS args;
    byte master[48];
    CK_ATTRIBUTE baseTmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,       master,          sizeof(master)         },
    };

    printf("\n--- TLS 1.2 key and MAC derive rollback of token keys ---\n");
    XMEMSET(master, 0x77, sizeof(master));
    rv = funcList->C_CreateObject(*session, baseTmpl,
                                  sizeof(baseTmpl) / sizeof(*baseTmpl), &base);
    check_rv(rv, CKR_OK, "create TLS master secret");
    if (rv != CKR_OK)
        return;

    n = fill_objects(*session, &ckTrue, 2);
    if (n == 0) {
        printf("SKIP: token object limit not reached\n");
        destroy_obj(*session, &base);
        return;
    }
    before = count_secret_keys(*session, 1);
    rv = tls12_key_derive(*session, base, CKK_GENERIC_SECRET, 128, &ckTrue,
                          &out);
    check(rv != CKR_OK, "TLS 1.2 derive past the token object limit fails");
    check(no_handles(&out), "no token handles returned");
    check(before != COUNT_FAILED && count_secret_keys(*session, 1) == before,
          "token MAC keys removed");
    /* Later store passes rewrite the token, so reload this state. */
    check(copy_dir(TEST_DIR, SNAP_DIR) == 0, "snapshot the token store");
    destroy_key_mat(*session, &out);
    empty_objects(*session, n);
    destroy_obj(*session, &base);

    funcList->C_Logout(*session);
    funcList->C_CloseSession(*session);
    *session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    rv = (copy_dir(SNAP_DIR, TEST_DIR) == 0) ? CKR_OK : CKR_GENERAL_ERROR;
    check_rv(rv, CKR_OK, "restore the token store");
    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    if (rv == CKR_OK)
        rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, session);
    }
    if (rv == CKR_OK)
        rv = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    check_rv(rv, CKR_OK, "reload the token");
    check(rv == CKR_OK && before != COUNT_FAILED &&
          count_secret_keys(*session, 1) == before,
          "token MAC keys still gone after a reload");
}
#endif
#endif

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
        return -1;
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

int main(int argc, char* argv[])
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif
    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 Derive Template and Rollback Test ===\n");

    rv = pkcs11_init();
    check_rv(rv, CKR_OK, "C_Initialize");
    if (rv == CKR_OK) {
        rv = pkcs11_setup_token();
        check_rv(rv, CKR_OK, "token setup");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
        check_rv(rv, CKR_OK, "C_OpenSession");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        check_rv(rv, CKR_OK, "C_Login");
    }
    if (rv == CKR_OK) {
#if defined(HAVE_ECC) && !defined(WOLFPKCS11_LEGACY_DERIVE_NO_INHERIT) && \
    !defined(WOLFPKCS11_NSS)
        test_ecdh_weaker_template(session);
#endif
#ifndef NO_DH
        test_dh_secret_length(session);
#endif
#ifdef WOLFSSL_HAVE_PRF
        test_tls12_rollback(session);
#ifdef TEST_TOKEN_RELOAD
        test_tls12_token_rollback(&session);
#endif
#endif
    }
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    return (test_failed == 0) ? 0 : 1;
}
