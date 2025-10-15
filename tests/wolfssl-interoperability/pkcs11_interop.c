/* pkcs11_interop.c - Interoperability test with wolfSSL
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
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/stat.h>

#include "user_settings.h"
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#ifdef WOLFSSL_SHA3
#include <wolfssl/wolfcrypt/sha3.h>
#endif
#include <wolfssl/wolfcrypt/wc_pkcs11.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <wolfpkcs11/pkcs11.h>

#include "tests/testdata.h"

#ifndef HAVE_ECC
#define HAVE_ECC
#define INTEROP_DEFINED_ECC 1
#endif
#include <wolfssl/certs_test.h>
#ifdef INTEROP_DEFINED_ECC
#undef HAVE_ECC
#undef INTEROP_DEFINED_ECC
#endif

#define rsa_2048_priv_der        client_key_der_2048
#define rsa_2048_priv_der_len    sizeof_client_key_der_2048
#define rsa_2048_pub_der         client_keypub_der_2048
#define rsa_2048_pub_der_len     sizeof_client_keypub_der_2048

#ifdef USE_CERT_BUFFERS_3072
#define rsa_3072_priv_der        client_key_der_3072
#define rsa_3072_priv_der_len    sizeof_client_key_der_3072
#define rsa_3072_pub_der         client_keypub_der_3072
#define rsa_3072_pub_der_len     sizeof_client_keypub_der_3072
#endif

#ifdef USE_CERT_BUFFERS_4096
#define rsa_4096_priv_der        client_key_der_4096
#define rsa_4096_priv_der_len    sizeof_client_key_der_4096
#define rsa_4096_pub_der         client_keypub_der_4096
#define rsa_4096_pub_der_len     sizeof_client_keypub_der_4096
#endif

#define ecc384_priv_der          ca_ecc_key_der_384
#define ecc384_priv_der_len      sizeof_ca_ecc_key_der_384

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef CKR_USER_ALREADY_LOGGED_IN
#define CKR_USER_ALREADY_LOGGED_IN 0x00000100UL
#endif

void wolfPKCS11_Debugging_On(void);
void wolfPKCS11_Debugging_Off(void);


static void set_token_env(void)
{
    const char* token_path = "./token-store";
#ifdef _WIN32
    _putenv("WOLFPKCS11_TOKEN_PATH=./token-store");
    _mkdir(token_path);
#else
    setenv("WOLFPKCS11_TOKEN_PATH", token_path, 1);
    mkdir(token_path, 0700);
#endif
}

static const char* error_to_string(int err)
{
    const char* str = wc_GetErrorString(err);
    return str != NULL ? str : "unknown";
}

static int destroy_objects_by_label(Pkcs11Token* token, CK_OBJECT_CLASS obj_class,
                                    const char* label)
{
    CK_SESSION_HANDLE session;
    int opened = 0;
    CK_ATTRIBUTE template[2];
    CK_OBJECT_HANDLE object;
    CK_ULONG count = 0;
    CK_RV rv;
    CK_RV login_rv = CKR_OK;
    int ret = 0;

    if (token == NULL || label == NULL)
        return BAD_FUNC_ARG;

    if (token->handle != CK_INVALID_HANDLE)
        session = token->handle;
    else {
        rv = token->func->C_OpenSession(token->slotId,
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
        if (rv != CKR_OK)
            return WC_HW_E;
        opened = 1;

        if (token->userPinLogin && token->userPin != NULL && token->userPinSz > 0) {
            login_rv = token->func->C_Login(session, CKU_USER,
                token->userPin, token->userPinSz);
            if (login_rv != CKR_OK && login_rv != CKR_USER_ALREADY_LOGGED_IN) {
                token->func->C_CloseSession(session);
                return WC_HW_E;
            }
        }
    }

    template[0].type = CKA_CLASS;
    template[0].pValue = &obj_class;
    template[0].ulValueLen = (CK_ULONG)sizeof(obj_class);
    template[1].type = CKA_LABEL;
    template[1].pValue = (void*)label;
    template[1].ulValueLen = (CK_ULONG)strlen(label);

    rv = token->func->C_FindObjectsInit(session, template, 2);
    if (rv == CKR_OK) {
        do {
            rv = token->func->C_FindObjects(session, &object, 1, &count);
            if (rv != CKR_OK)
                break;
            if (count > 0)
                token->func->C_DestroyObject(session, object);
        } while (rv == CKR_OK && count > 0);
        token->func->C_FindObjectsFinal(session);
    }

    if (opened) {
        if (token->userPinLogin && login_rv == CKR_OK)
            token->func->C_Logout(session);
        token->func->C_CloseSession(session);
    }

    return ret;
}

static int init_token(const char* module_path, Pkcs11Dev* dev,
                      Pkcs11Token* token, CK_SLOT_ID* slot_id)
{
    CK_UTF8CHAR so_pin[]   = "password123456";
    CK_UTF8CHAR user_pin_l[] = "interop-user";
    static const char token_label_text[] = "wolfPKCS11-Interop";
    CK_UTF8CHAR label[32];
    CK_RV rv;
    CK_SLOT_ID_PTR slots = NULL;
    CK_ULONG slot_cnt = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int ret = 0;

    set_token_env();

    ret = wc_Pkcs11_Initialize(dev, module_path, NULL);
    if (ret != 0) {
        fprintf(stderr, "wc_Pkcs11_Initialize failed: %d (%s)\n", ret,
                error_to_string(ret));
        return ret;
    }

    rv = dev->func->C_GetSlotList(CK_FALSE, NULL, &slot_cnt);
    if (rv != CKR_OK || slot_cnt == 0) {
        fprintf(stderr, "C_GetSlotList failed: 0x%lx\n", (unsigned long)rv);
        ret = WC_HW_E;
        goto exit;
    }

    slots = (CK_SLOT_ID_PTR)calloc(slot_cnt, sizeof(CK_SLOT_ID));
    if (slots == NULL) {
        ret = MEMORY_E;
        goto exit;
    }
    rv = dev->func->C_GetSlotList(CK_FALSE, slots, &slot_cnt);
    if (rv != CKR_OK || slot_cnt == 0) {
        fprintf(stderr, "C_GetSlotList (2) failed: 0x%lx\n", (unsigned long)rv);
        ret = WC_HW_E;
        goto exit;
    }

    *slot_id = slots[0];

    memset(label, ' ', sizeof(label));
    memcpy(label, token_label_text,
           strlen(token_label_text) < sizeof(label) ? strlen(token_label_text)
                                                    : sizeof(label));

    rv = dev->func->C_InitToken(*slot_id, so_pin,
                                (CK_ULONG)strlen((const char*)so_pin), label);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_InitToken failed: 0x%lx\n", (unsigned long)rv);
        ret = WC_HW_E;
        goto exit;
    }

    rv = dev->func->C_OpenSession(*slot_id,
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_OpenSession failed: 0x%lx\n", (unsigned long)rv);
        ret = WC_HW_E;
        goto exit;
    }

    rv = dev->func->C_Login(session, CKU_SO, so_pin,
                             (CK_ULONG)strlen((const char*)so_pin));
    if (rv != CKR_OK) {
        fprintf(stderr, "SO login failed: 0x%lx\n", (unsigned long)rv);
        ret = WC_HW_E;
        goto exit;
    }

    rv = dev->func->C_InitPIN(session, user_pin_l,
                              (CK_ULONG)strlen((const char*)user_pin_l));
    if (rv != CKR_OK) {
        fprintf(stderr, "C_InitPIN failed: 0x%lx\n", (unsigned long)rv);
        ret = WC_HW_E;
        goto exit;
    }

    dev->func->C_Logout(session);
    dev->func->C_CloseSession(session);
    session = CK_INVALID_HANDLE;

    ret = wc_Pkcs11Token_Init(token, dev, (int)(*slot_id),
                              "wolfpkcs11", user_pin_l,
                              (int)strlen((const char*)user_pin_l));
    if (ret != 0) {
        fprintf(stderr, "wc_Pkcs11Token_Init failed: %d (%s)\n", ret,
                error_to_string(ret));
        goto exit;
    }

    ret = wc_Pkcs11Token_Open(token, 1);
    if (ret != 0) {
        fprintf(stderr, "wc_Pkcs11Token_Open failed: %d (%s)\n", ret,
                error_to_string(ret));
        goto exit;
    }

exit:
    if (session != CK_INVALID_HANDLE)
        dev->func->C_CloseSession(session);
    free(slots);
    if (ret != 0) {
        wc_Pkcs11Token_Final(token);
        wc_Pkcs11_Finalize(dev);
    }
    return ret;
}

static int compare_bytes(const byte* a, const byte* b, size_t len)
{
    return memcmp(a, b, len) == 0 ? 0 : -1;
}

static void dump_buffer(const char* label, const byte* buf, size_t len)
{
    size_t i;
    fprintf(stderr, "%s: ", label);
    for (i = 0; i < len; i++)
        fprintf(stderr, "%02X", buf[i]);
    fprintf(stderr, "\n");
}

static int test_aes_gcm(Pkcs11Token* token, int dev_id)
{
    int ret;
    Aes aes;
    byte cipher[ARRAY_SIZE(aes_gcm_plain)];
    byte plain[ARRAY_SIZE(aes_gcm_plain)];
    byte tag[ARRAY_SIZE(aes_gcm_tag)];

    ret = wc_AesInit(&aes, NULL, dev_id);
    if (ret != 0)
        return ret;

    ret = wc_AesGcmSetKey(&aes, aes_gcm_key, (word32)sizeof(aes_gcm_key));
    if (ret != 0)
        goto done;

    memcpy(aes.devKey, aes_gcm_key, sizeof(aes_gcm_key));
    aes.keylen = (int)sizeof(aes_gcm_key);

    {
        static const char label[] = "aes-gcm-interop";
        aes.labelLen = (int)sizeof(label) - 1;
        memcpy(aes.label, label, aes.labelLen);
        destroy_objects_by_label(token, CKO_SECRET_KEY, label);
    }

    ret = wc_Pkcs11StoreKey(token, PKCS11_KEY_TYPE_AES_GCM, 0, &aes);
    if (ret != 0)
        goto done;

    ret = wc_AesGcmEncrypt(&aes, cipher, aes_gcm_plain,
                           (word32)sizeof(aes_gcm_plain),
                           aes_gcm_iv, (word32)sizeof(aes_gcm_iv),
                           tag, (word32)sizeof(tag),
                           aes_gcm_aad, (word32)sizeof(aes_gcm_aad));
    if (ret != 0)
        goto done;

    if (compare_bytes(cipher, aes_gcm_cipher, sizeof(cipher)) != 0 ||
        compare_bytes(tag, aes_gcm_tag, sizeof(tag)) != 0) {
        dump_buffer("cipher", cipher, sizeof(cipher));
        dump_buffer("expect", aes_gcm_cipher, sizeof(aes_gcm_cipher));
        dump_buffer("tag", tag, sizeof(tag));
        dump_buffer("tag-exp", aes_gcm_tag, sizeof(aes_gcm_tag));
        ret = WC_HW_E;
        goto done;
    }

    ret = wc_AesGcmDecrypt(&aes, plain, cipher, (word32)sizeof(cipher),
                           aes_gcm_iv, (word32)sizeof(aes_gcm_iv),
                           tag, (word32)sizeof(tag),
                           aes_gcm_aad, (word32)sizeof(aes_gcm_aad));
    if (ret != 0)
        goto done;

    if (compare_bytes(plain, aes_gcm_plain, sizeof(plain)) != 0) {
        dump_buffer("plain", plain, sizeof(plain));
        dump_buffer("plain-exp", aes_gcm_plain, sizeof(aes_gcm_plain));
        ret = WC_HW_E;
    }

done:
    wc_AesFree(&aes);
    destroy_objects_by_label(token, CKO_SECRET_KEY, "aes-gcm-interop");
    return ret;
}

static int test_hmac_sha256(Pkcs11Token* token, int dev_id)
{
    int ret;
    Hmac hmac;
    byte digest[ARRAY_SIZE(hmac_digest)];

    ret = wc_HmacInit(&hmac, NULL, dev_id);
    if (ret != 0)
        return ret;

    ret = wc_HmacSetKey(&hmac, WC_SHA256, hmac_key, (word32)sizeof(hmac_key));
    if (ret != 0)
        goto done;

    {
        static const char label[] = "hmac-sha256-interop";
        hmac.labelLen = (int)sizeof(label) - 1;
        memcpy(hmac.label, label, hmac.labelLen);
        destroy_objects_by_label(token, CKO_SECRET_KEY, label);
    }

    ret = wc_Pkcs11StoreKey(token, PKCS11_KEY_TYPE_HMAC, 0, &hmac);
    if (ret != 0)
        goto done;

    ret = wc_HmacUpdate(&hmac, hmac_msg, (word32)sizeof(hmac_msg));
    if (ret != 0)
        goto done;

    ret = wc_HmacFinal(&hmac, digest);
    if (ret != 0)
        goto done;

    if (compare_bytes(digest, hmac_digest, sizeof(digest)) != 0) {
        dump_buffer("hmac", digest, sizeof(digest));
        dump_buffer("hmac-exp", hmac_digest, sizeof(hmac_digest));
        ret = WC_HW_E;
    }

done:
    wc_HmacFree(&hmac);
    destroy_objects_by_label(token, CKO_SECRET_KEY, "hmac-sha256-interop");
    return ret;
}

#ifdef WOLFSSL_SHA224
static int test_sha224_digest(int dev_id)
{
    int ret;
    wc_Sha224 sha;
    byte digest[WC_SHA224_DIGEST_SIZE];

    (void)dev_id;

    ret = wc_InitSha224_ex(&sha, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_Sha224Update(&sha, sha_test_msg, (word32)sizeof(sha_test_msg));
    if (ret == 0)
        ret = wc_Sha224Final(&sha, digest);
    wc_Sha224Free(&sha);

    if (ret == 0 && compare_bytes(digest, sha224_expected,
                                   sizeof(sha224_expected)) != 0)
        ret = WC_HW_E;

    return ret;
}
#endif /* WOLFSSL_SHA224 */

static int test_sha256_digest(int dev_id)
{
    int ret;
    wc_Sha256 sha;
    byte digest[WC_SHA256_DIGEST_SIZE];

    (void)dev_id;

    ret = wc_InitSha256_ex(&sha, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_Sha256Update(&sha, sha_test_msg, (word32)sizeof(sha_test_msg));
    if (ret == 0)
        ret = wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);

    if (ret == 0 && compare_bytes(digest, sha256_expected,
                                   sizeof(sha256_expected)) != 0)
        ret = WC_HW_E;

    return ret;
}

#ifdef WOLFSSL_SHA384
static int test_sha384_digest(int dev_id)
{
    int ret;
    wc_Sha384 sha;
    byte digest[WC_SHA384_DIGEST_SIZE];

    (void)dev_id;

    ret = wc_InitSha384_ex(&sha, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_Sha384Update(&sha, sha_test_msg, (word32)sizeof(sha_test_msg));
    if (ret == 0)
        ret = wc_Sha384Final(&sha, digest);
    wc_Sha384Free(&sha);

    if (ret == 0 && compare_bytes(digest, sha384_expected,
                                   sizeof(sha384_expected)) != 0)
        ret = WC_HW_E;

    return ret;
}
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
static int test_sha512_digest(int dev_id)
{
    int ret;
    wc_Sha512 sha;
    byte digest[WC_SHA512_DIGEST_SIZE];

    (void)dev_id;

    ret = wc_InitSha512_ex(&sha, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_Sha512Update(&sha, sha_test_msg, (word32)sizeof(sha_test_msg));
    if (ret == 0)
        ret = wc_Sha512Final(&sha, digest);
    wc_Sha512Free(&sha);

    if (ret == 0 && compare_bytes(digest, sha512_expected,
                                   sizeof(sha512_expected)) != 0)
        ret = WC_HW_E;

    return ret;
}
#endif /* WOLFSSL_SHA512 */

#ifdef WOLFSSL_SHA3
static int test_sha3_256_digest(int dev_id)
{
    int ret;
    wc_Sha3 sha;
    byte digest[WC_SHA3_256_DIGEST_SIZE];

    (void)dev_id;

    ret = wc_InitSha3_256(&sha, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_Sha3_256_Update(&sha, sha_test_msg,
                             (word32)sizeof(sha_test_msg));
    if (ret == 0)
        ret = wc_Sha3_256_Final(&sha, digest);
    wc_Sha3_256_Free(&sha);

    if (ret == 0 && compare_bytes(digest, sha3_256_expected,
                                   sizeof(sha3_256_expected)) != 0)
        ret = WC_HW_E;

    return ret;
}
#endif /* WOLFSSL_SHA3 */

static int rsa_decode_private_key_der(RsaKey* key, int devId,
    const byte* priv_der, word32 priv_len)
{
    int ret;
    word32 idx = 0;

    ret = wc_InitRsaKey_ex(key, NULL, devId);
    if (ret != 0)
        return ret;

    ret = wc_RsaPrivateKeyDecode(priv_der, &idx, key, priv_len);
    if (ret != 0)
        wc_FreeRsaKey(key);

    return ret;
}

static int rsa_decode_public_key_der(RsaKey* key, int devId,
    const byte* pub_der, word32 pub_len)
{
    int ret;
    word32 idx = 0;

    ret = wc_InitRsaKey_ex(key, NULL, devId);
    if (ret != 0)
        return ret;

    ret = wc_RsaPublicKeyDecode(pub_der, &idx, key, pub_len);
    if (ret != 0)
        wc_FreeRsaKey(key);

    return ret;
}

static int test_rsa_sign_verify_der(Pkcs11Token* token, int dev_id,
    const byte* priv_der, word32 priv_len, const byte* pub_der,
    word32 pub_len, const char* label)
{
    int ret;
    RsaKey key;
    RsaKey pubKey;
    byte message[] = "wolfPKCS11 interoperability";
    byte digest[WC_SHA256_DIGEST_SIZE];
    byte signature[512];
    byte recovered[512];
    word32 sig_len;
    word32 recovered_len;
    WC_RNG rng;

    memset(&key, 0, sizeof(key));
    memset(&pubKey, 0, sizeof(pubKey));

    ret = rsa_decode_private_key_der(&key, dev_id, priv_der, priv_len);
    if (ret != 0)
        return ret;

    if (label != NULL) {
        size_t len = strlen(label);
        if (len > sizeof(key.label))
            len = sizeof(key.label);
        key.labelLen = (int)len;
        memcpy(key.label, label, key.labelLen);
        destroy_objects_by_label(token, CKO_PRIVATE_KEY, label);
    }
    key.idLen = 1;
    key.id[0] = 0x01;

    if (ret == 0)
        ret = wc_mp_to_bigint(&key.n, &key.n.raw);
    if (ret == 0)
        ret = wc_mp_to_bigint(&key.e, &key.e.raw);
#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
    if (ret == 0)
        ret = wc_mp_to_bigint(&key.d, &key.d.raw);
    if (ret == 0)
        ret = wc_mp_to_bigint(&key.p, &key.p.raw);
    if (ret == 0)
        ret = wc_mp_to_bigint(&key.q, &key.q.raw);
    if (ret == 0)
        ret = wc_mp_to_bigint(&key.dP, &key.dP.raw);
    if (ret == 0)
        ret = wc_mp_to_bigint(&key.dQ, &key.dQ.raw);
    if (ret == 0)
        ret = wc_mp_to_bigint(&key.u, &key.u.raw);
#endif
    if (ret != 0)
        goto done_key;

    ret = wc_InitRng_ex(&rng, NULL, dev_id);
    if (ret != 0)
        goto done_key;

    ret = rsa_decode_public_key_der(&pubKey, dev_id, pub_der, pub_len);
    if (ret != 0)
        goto done_rng;

    ret = wc_Sha256Hash(message, (word32)sizeof(message) - 1, digest);
    if (ret != 0)
        goto done_rng;

    ret = wc_Pkcs11StoreKey(token, PKCS11_KEY_TYPE_RSA, 0, &key);
    if (ret != 0) {
        fprintf(stderr, "wc_Pkcs11StoreKey(RSA) failed: %d (%s)\n", ret,
                error_to_string(ret));
        goto done_rng;
    }

    sig_len = (word32)sizeof(signature);
    ret = wc_RsaPSS_Sign_ex(digest, sizeof(digest), signature, sig_len,
        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, RSA_PSS_SALT_LEN_DEFAULT, &key, &rng);
    if (ret < 0) {
        fprintf(stderr, "wc_RsaPSS_Sign_ex failed: %d (%s)\n", ret,
                error_to_string(ret));
        goto done_rng;
    }
    sig_len = (word32)ret;

    ret = wc_RsaPSS_Verify_ex(signature, sig_len, recovered, sizeof(recovered),
        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, RSA_PSS_SALT_LEN_DEFAULT, &pubKey);
    if (ret < 0) {
        fprintf(stderr, "wc_RsaPSS_Verify_ex failed: %d (%s)\n", ret,
                error_to_string(ret));
        goto done_rng;
    }
    recovered_len = (word32)ret;

    ret = wc_RsaPSS_CheckPadding(digest, sizeof(digest), recovered,
                                 recovered_len, WC_HASH_TYPE_SHA256);
    if (ret != 0) {
        fprintf(stderr, "PSS padding check failed: %d\n", ret);
        goto done_rng;
    }

    ret = 0;

done_rng:
    wc_FreeRng(&rng);
    wc_FreeRsaKey(&pubKey);

done_key:
    wc_FreeRsaKey(&key);
    if (label != NULL)
        destroy_objects_by_label(token, CKO_PRIVATE_KEY, label);
    return ret;
}

static int test_rsa_sign_verify(Pkcs11Token* token, int dev_id)
{
    return test_rsa_sign_verify_der(token, dev_id,
        rsa_2048_priv_der, (word32)rsa_2048_priv_der_len,
        rsa_2048_pub_der, (word32)rsa_2048_pub_der_len,
        "rsa-2048");
}
static int test_rsa_sign_verify_3072(Pkcs11Token* token, int dev_id)
{
    return test_rsa_sign_verify_der(token, dev_id,
        rsa_3072_priv_der, (word32)rsa_3072_priv_der_len,
        rsa_3072_pub_der, (word32)rsa_3072_pub_der_len,
        "rsa-3072");
}

static int test_rsa_sign_verify_4096(Pkcs11Token* token, int dev_id)
{
    return test_rsa_sign_verify_der(token, dev_id,
        rsa_4096_priv_der, (word32)rsa_4096_priv_der_len,
        rsa_4096_pub_der, (word32)rsa_4096_pub_der_len,
        "rsa-4096");
}

static int run_aes_cbc_vector(Pkcs11Token* token, int dev_id,
    const byte* key, word32 keyLen, const byte* iv,
    const byte* plain, word32 dataLen, const byte* expected,
    const char* label)
{
    int ret = 0;
    Aes aes;
    byte cipher[32];
    byte plainOut[32];

    if (dataLen > (word32)sizeof(cipher))
        return BAD_FUNC_ARG;

    ret = wc_AesInit(&aes, NULL, dev_id);
    if (ret != 0)
        return ret;

    ret = wc_AesSetKey(&aes, key, keyLen, iv, AES_ENCRYPTION);
    if (ret != 0)
        goto done;
    aes.keylen = (int)keyLen;
    memcpy(aes.devKey, key, keyLen);

    if (label != NULL) {
        size_t len = strlen(label);
        if (len > sizeof(aes.label))
            len = sizeof(aes.label);
        aes.labelLen = (int)len;
        memcpy(aes.label, label, aes.labelLen);
        destroy_objects_by_label(token, CKO_SECRET_KEY, label);
    }

    ret = wc_Pkcs11StoreKey(token, PKCS11_KEY_TYPE_AES_CBC, 0, &aes);
    if (ret != 0)
        goto done;

    memset(cipher, 0xA5, dataLen);
    ret = wc_AesCbcEncrypt(&aes, cipher, plain, dataLen);
    if (ret != 0)
        goto done;
    if (compare_bytes(cipher, expected, dataLen) != 0) {
        dump_buffer("cbc-enc", cipher, dataLen);
        dump_buffer("cbc-exp", expected, dataLen);
        ret = WC_HW_E;
        goto done;
    }

    ret = wc_AesSetKey(&aes, key, keyLen, iv, AES_DECRYPTION);
    if (ret != 0)
        goto done;

    memset(plainOut, 0x5A, dataLen);
    ret = wc_AesCbcDecrypt(&aes, plainOut, cipher, dataLen);
    if (ret != 0)
        goto done;
    if (compare_bytes(plainOut, plain, dataLen) != 0) {
        dump_buffer("cbc-dec", plainOut, dataLen);
        dump_buffer("cbc-exp", plain, dataLen);
        ret = WC_HW_E;
    }

done:
    wc_AesFree(&aes);
    return ret;
}

static int run_aes_ctr_vector(Pkcs11Token* token, int dev_id,
    const byte* key, word32 keyLen, const byte* iv,
    const byte* plain, word32 dataLen, const byte* expected,
    const char* label)
{
    int ret = 0;
    Aes aes;
    byte cipher[32];
    byte plainOut[32];

    if (dataLen > (word32)sizeof(cipher))
        return BAD_FUNC_ARG;

    ret = wc_AesInit(&aes, NULL, dev_id);
    if (ret != 0)
        return ret;

    ret = wc_AesSetKey(&aes, key, keyLen, iv, AES_ENCRYPTION);
    if (ret != 0)
        goto done;
    aes.keylen = (int)keyLen;
    memcpy(aes.devKey, key, keyLen);

    if (label != NULL) {
        size_t len = strlen(label);
        if (len > sizeof(aes.label))
            len = sizeof(aes.label);
        aes.labelLen = (int)len;
        memcpy(aes.label, label, aes.labelLen);
        destroy_objects_by_label(token, CKO_SECRET_KEY, label);
    }

    ret = wc_Pkcs11StoreKey(token, PKCS11_KEY_TYPE_AES_CBC, 0, &aes);
    if (ret != 0)
        goto done;

    memset(cipher, 0xA5, dataLen);
    ret = wc_AesCtrEncrypt(&aes, cipher, plain, dataLen);
    if (ret != 0)
        goto done;
    if (compare_bytes(cipher, expected, dataLen) != 0) {
        dump_buffer("ctr-enc", cipher, dataLen);
        dump_buffer("ctr-exp", expected, dataLen);
        ret = WC_HW_E;
        goto done;
    }

    ret = wc_AesSetKey(&aes, key, keyLen, iv, AES_ENCRYPTION);
    if (ret != 0)
        goto done;

    memset(plainOut, 0x5A, dataLen);
    ret = wc_AesCtrEncrypt(&aes, plainOut, cipher, dataLen);
    if (ret != 0)
        goto done;
    if (compare_bytes(plainOut, plain, dataLen) != 0) {
        dump_buffer("ctr-dec", plainOut, dataLen);
        dump_buffer("ctr-exp", plain, dataLen);
        ret = WC_HW_E;
    }

done:
    wc_AesFree(&aes);
    if (label != NULL)
        destroy_objects_by_label(token, CKO_SECRET_KEY, label);
    return ret;
}

/* Test AES-CBC encryption/decryption */
static int test_aes_cbc(Pkcs11Token* token, int dev_id)
{
    return run_aes_cbc_vector(token, dev_id, aes_cbc_key,
        (word32)sizeof(aes_cbc_key), aes_cbc_iv, aes_cbc_plain,
        (word32)sizeof(aes_cbc_plain), aes_cbc_cipher,
        "aes-cbc-128");
}

static int test_aes_cbc_256(Pkcs11Token* token, int dev_id)
{
    return run_aes_cbc_vector(token, dev_id, aes_cbc256_key,
        (word32)sizeof(aes_cbc256_key), aes_cbc256_iv, aes_cbc_plain,
        (word32)sizeof(aes_cbc_plain), aes_cbc256_cipher,
        "aes-cbc-256");
}

/* Test AES-CTR encryption/decryption */
static int test_aes_ctr(Pkcs11Token* token, int dev_id)
{
    return run_aes_ctr_vector(token, dev_id, aes_ctr_key,
        (word32)sizeof(aes_ctr_key), aes_ctr_iv, aes_ctr_plain,
        (word32)sizeof(aes_ctr_plain), aes_ctr_cipher,
        "aes-ctr-128");
}

static int test_aes_ctr_256(Pkcs11Token* token, int dev_id)
{
    return run_aes_ctr_vector(token, dev_id, aes_ctr256_key,
        (word32)sizeof(aes_ctr256_key), aes_ctr256_iv, aes_ctr_plain,
        (word32)sizeof(aes_ctr_plain), aes_ctr256_cipher,
        "aes-ctr-256");
}
static int test_ecc_sign_verify_der(Pkcs11Token* token, int devId,
    const byte* priv_der, word32 priv_len, int curveId,
    const char* name, int generate)
{
    int ret = 0;
    ecc_key eccPriv;
    ecc_key eccPub;
    WC_RNG rng;
    byte hash[32], sig[144];
    word32 hashSz = sizeof(hash);
    word32 sigSz = sizeof(sig);
    int verify = 0;
    byte pubBuf[150];
    word32 pubSz = (word32)sizeof(pubBuf);

    (void)generate;

    memset(hash, 9, sizeof(hash));

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    ret = wc_ecc_init_ex(&eccPriv, NULL, INVALID_DEVID);
    if (ret != 0)
        goto done_rng;

    if (priv_der != NULL && priv_len > 0) {
        word32 idx = 0;
        ret = wc_EccPrivateKeyDecode(priv_der, &idx, &eccPriv, priv_len);
    }
    else {
        int keySz = wc_ecc_get_curve_size_from_id(curveId);
        if (keySz <= 0)
            ret = BAD_FUNC_ARG;
        else
            ret = wc_ecc_make_key_ex(&rng, keySz, &eccPriv, curveId);
    }
    if (ret != 0)
        goto done_priv;

    if (curveId <= 0 && eccPriv.dp != NULL)
        curveId = eccPriv.dp->id;

    ret = wc_ecc_init_ex(&eccPub, NULL, INVALID_DEVID);
    if (ret != 0)
        goto done_priv;

    ret = wc_ecc_export_x963(&eccPriv, pubBuf, &pubSz);
    if (ret == 0)
        ret = wc_ecc_import_x963_ex(pubBuf, pubSz, &eccPub, curveId);
    if (ret != 0)
        goto done_pub;

    ret = wc_ecc_sign_hash(hash, hashSz, sig, &sigSz, &rng, &eccPriv);
    if (ret < 0)
        goto done_pub;

    if (name != NULL) {
        size_t len = strlen(name);
        if (len > sizeof(eccPriv.label))
            len = sizeof(eccPriv.label);
        eccPriv.labelLen = (int)len;
        memcpy(eccPriv.label, name, eccPriv.labelLen);
        if (token != NULL)
            destroy_objects_by_label(token, CKO_PRIVATE_KEY, name);
    }

    if (token != NULL)
        (void)wc_Pkcs11StoreKey(token, PKCS11_KEY_TYPE_EC, 0, &eccPriv);

    ret = wc_ecc_verify_hash(sig, sigSz, hash, (int)hashSz, &verify, &eccPub);
    if (ret < 0 || !verify) {
        if (ret >= 0)
            ret = BAD_FUNC_ARG;
        goto done_pub;
    }

    ret = 0;

done_pub:
    wc_ecc_free(&eccPub);
done_priv:
    wc_ecc_free(&eccPriv);
done_rng:
    wc_FreeRng(&rng);
    if (token != NULL && name != NULL)
        destroy_objects_by_label(token, CKO_PRIVATE_KEY, name);
    return ret;
}

static int test_ecc_p256(Pkcs11Token* token, int devId)
{
    return test_ecc_sign_verify_der(token, devId, ecc_clikey_der_256,
        (word32)sizeof_ecc_clikey_der_256, ECC_SECP256R1, "secp256r1", 0);
}

static int test_ecc_p384(Pkcs11Token* token, int devId)
{
    return test_ecc_sign_verify_der(token, devId, ecc384_priv_der,
        (word32)ecc384_priv_der_len, ECC_SECP384R1, "secp384r1", 0);
}

#ifdef HAVE_ECC521
static int test_ecc_p521(Pkcs11Token* token, int devId)
{
    return test_ecc_sign_verify_der(token, devId, NULL, 0,
        ECC_SECP521R1, "secp521r1", 1);
}
#endif

/* Test AES-XTS encryption/decryption */
int test_aes_xts(Pkcs11Token* token, int dev_id)
{
    int ret = 0;
    XtsAes xts;
    byte cipher[sizeof(aes_xts_plain)];
    byte plain[sizeof(aes_xts_plain)];
    byte tweak[sizeof(aes_xts_tweak)];

    ret = wc_AesXtsInit(&xts, NULL, dev_id);
    if (ret != 0) return ret;

    ret = wc_AesXtsSetKey(&xts, aes_xts_key, (word32)sizeof(aes_xts_key),
                          AES_ENCRYPTION, NULL, 0);
    if (ret != 0) goto done;

    memcpy(tweak, aes_xts_tweak, sizeof(tweak));
    memset(cipher, 0xA5, sizeof(cipher));
    memset(plain, 0x5A, sizeof(plain));

    {
        static const char label[] = "aes-xts-interop";
        size_t len = sizeof(label) - 1;
        if (len > sizeof(xts.aes.label))
            len = sizeof(xts.aes.label);
        xts.aes.labelLen = (int)len;
        memcpy(xts.aes.label, label, xts.aes.labelLen);
        destroy_objects_by_label(token, CKO_SECRET_KEY, label);
    }

    ret = wc_Pkcs11StoreKey(token, PKCS11_KEY_TYPE_AES_CBC, 0, &xts);
    if (ret != 0) goto done;

    ret = wc_AesXtsEncrypt(&xts, cipher, aes_xts_plain,
                           (word32)sizeof(aes_xts_plain), tweak,
                           (word32)sizeof(tweak));
    if (ret != 0) goto done;
    if (compare_bytes(cipher, aes_xts_cipher, sizeof(cipher)) != 0) {
        dump_buffer("xts-enc", cipher, sizeof(cipher));
        dump_buffer("xts-exp", aes_xts_cipher, sizeof(aes_xts_cipher));
        ret = WC_HW_E;
        goto done;
    }

    memcpy(tweak, aes_xts_tweak, sizeof(tweak));
    memset(plain, 0x5A, sizeof(plain));

    ret = wc_AesXtsSetKey(&xts, aes_xts_key, (word32)sizeof(aes_xts_key),
                          AES_DECRYPTION, NULL, 0);
    if (ret != 0) goto done;

    ret = wc_AesXtsDecrypt(&xts, plain, cipher, (word32)sizeof(cipher),
                           tweak, (word32)sizeof(tweak));
    if (ret != 0) goto done;

    if (compare_bytes(plain, aes_xts_plain, sizeof(plain)) != 0) {
        dump_buffer("xts-dec", plain, sizeof(plain));
        dump_buffer("xts-exp", aes_xts_plain, sizeof(aes_xts_plain));
        ret = WC_HW_E;
    }

done:
    wc_AesXtsFree(&xts);
    destroy_objects_by_label(token, CKO_SECRET_KEY, "aes-xts-interop");
    return ret;
}


int main(int argc, char** argv)
{
    const char* module_path = getenv("WOLFPKCS11_MODULE");
    CK_SLOT_ID slot_id = 0;
    Pkcs11Dev dev;
    Pkcs11Token token;
    int dev_id = 23;
    int ret;
    int failures = 0;

    if (module_path == NULL) {
        module_path = (argc > 1) ? argv[1] : "./build/libwolfpkcs11-interop.so";
    }

    {
        static char resolved_path[PATH_MAX];
        if (realpath(module_path, resolved_path) != NULL)
            module_path = resolved_path;
    }

    memset(&dev, 0, sizeof(dev));
    memset(&token, 0, sizeof(token));

    {
        void* probe = dlopen(module_path, RTLD_NOW | RTLD_LOCAL);
        if (probe == NULL) {
            fprintf(stderr, "dlopen failed for %s: %s\n", module_path, dlerror());
            return EXIT_FAILURE;
        }
        void (*debug_on)(void) = (void (*)(void))dlsym(probe,
                                                       "wolfPKCS11_Debugging_On");
        if (debug_on != NULL)
            debug_on();
        dlclose(probe);
    }

    ret = init_token(module_path, &dev, &token, &slot_id);
    if (ret != 0)
        return EXIT_FAILURE;

    ret = wc_CryptoCb_RegisterDevice(dev_id, wc_Pkcs11_CryptoDevCb, &token);
    if (ret != 0) {
        fprintf(stderr, "wc_CryptoCb_RegisterDevice failed: %d\n", ret);
        failures++;
        goto cleanup;
    }

    ret = test_aes_gcm(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "AES-GCM test failed: %d (%s)\n", ret, error_to_string(ret));
        failures++;
    } else {
        printf("AES-GCM	test_passed!\n");
    }

    ret = test_hmac_sha256(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "HMAC-SHA256 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("HMAC-SHA256	test_passed!\n");
    }

#ifdef WOLFSSL_SHA224
    ret = test_sha224_digest(dev_id);
    if (ret != 0) {
        fprintf(stderr, "SHA-224 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("SHA-224	test_passed!\n");
    }
#endif

    ret = test_sha256_digest(dev_id);
    if (ret != 0) {
        fprintf(stderr, "SHA-256 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("SHA-256	test_passed!\n");
    }

#ifdef WOLFSSL_SHA384
    ret = test_sha384_digest(dev_id);
    if (ret != 0) {
        fprintf(stderr, "SHA-384 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("SHA-384	test_passed!\n");
    }
#endif

#ifdef WOLFSSL_SHA512
    ret = test_sha512_digest(dev_id);
    if (ret != 0) {
        fprintf(stderr, "SHA-512 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("SHA-512	test_passed!\n");
    }
#endif

#ifdef WOLFSSL_SHA3
    ret = test_sha3_256_digest(dev_id);
    if (ret != 0) {
        fprintf(stderr, "SHA3-256 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("SHA3-256	test_passed!\n");
    }
#endif

    ret = test_rsa_sign_verify(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "RSA PKCS#1 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("RSA PKCS#1	test_passed!\n");
    }

    ret = test_rsa_sign_verify_3072(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "RSA-3072 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("RSA-3072	test_passed!\n");
    }

    ret = test_rsa_sign_verify_4096(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "RSA-4096 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("RSA-4096	test_passed!\n");
    }

    /* New AES mode tests */
    ret = test_aes_cbc(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "AES-CBC test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("AES-CBC	test_passed!\n");
    }

    ret = test_aes_cbc_256(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "AES-CBC (256-bit) test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("AES-CBC (256-bit)	test_passed!\n");
    }

    ret = test_aes_ctr(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "AES-CTR test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("AES-CTR	test_passed!\n");
    }

    ret = test_aes_ctr_256(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "AES-CTR (256-bit) test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("AES-CTR (256-bit)	test_passed!\n");
    }

    /* ---------- AES-XTS test ---------- */
    ret = test_aes_xts(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "AES-XTS test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("AES-XTS	test_passed!\n");
    }

    ret = test_ecc_p256(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "ECDSA test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("ECDSA	test_passed!\n");
    }

    ret = test_ecc_p384(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "ECDSA P-384 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("ECDSA P-384	test_passed!\n");
    }

#ifdef HAVE_ECC521
    ret = test_ecc_p521(&token, dev_id);
    if (ret != 0) {
        fprintf(stderr, "ECDSA P-521 test failed: %d (%s)\n", ret,
                error_to_string(ret));
        failures++;
    } else {
        printf("ECDSA P-521	test_passed!\n");
    }
#endif

cleanup:
    wc_CryptoCb_UnRegisterDevice(dev_id);
    wc_Pkcs11Token_Close(&token);
    wc_Pkcs11Token_Final(&token);
    wc_Pkcs11_Finalize(&dev);

    if (failures == 0) {
        printf("All wolfPKCS11 interoperability tests passed.\n");
        return EXIT_SUCCESS;
    }

    fprintf(stderr, "%d test(s) failed.\n", failures);
    return EXIT_FAILURE;
}
#ifdef __cplusplus
extern "C" {
#endif
void wolfPKCS11_Debugging_On(void);
void wolfPKCS11_Debugging_Off(void);
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif
void wolfPKCS11_Debugging_On(void);
void wolfPKCS11_Debugging_Off(void);
#ifdef __cplusplus
}
#endif
