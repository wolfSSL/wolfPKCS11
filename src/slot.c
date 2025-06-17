/* slot.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <wolfpkcs11/pkcs11.h>
#include <wolfpkcs11/internal.h>


/**
 * Gets a list of slot identifiers for available slots.
 *
 * @param  tokenPresent  [in]      Require slot to have a token inserted.
 * @param  pSlotList     [in]      Array of slot ids to fill.
 *                                 NULL indicates the length is required.
 * @param  pulCount      [in,out]  On in, the number of array entries in
 *                                 pSlotList.
 *                                 On out, the number of slot ids put in array.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_ARGUMENTS_BAD when pulCount is NULL or tokenPresent isn't
 *          a valid boolean value.
 *          CKR_BUFFER_TOO_SMALL when more slot ids match that entries in array.
 *          CKR_OK on success.
 */
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount)
{
    int ret;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (tokenPresent != CK_FALSE && tokenPresent != CK_TRUE)
        return CKR_ARGUMENTS_BAD;
    if (pulCount == NULL)
        return CKR_ARGUMENTS_BAD;

    ret = WP11_GetSlotList(tokenPresent, pSlotList, pulCount);
    if (ret == BUFFER_E)
        return CKR_BUFFER_TOO_SMALL;

    return CKR_OK;
}

/* Index into slot id string to place number. */
#define SLOT_ID_IDX     20

/* Template for slot information. */
static CK_SLOT_INFO slotInfoTemplate = {
    "wolfSSL HSM slot ID xx",
    "wolfpkcs11",
    CKF_TOKEN_PRESENT
    ,
    { WOLFPKCS11_MAJOR_VERSION, WOLFPKCS11_MINOR_VERSION },
    { WOLFPKCS11_MAJOR_VERSION, WOLFPKCS11_MINOR_VERSION }
};

/**
 * Get information on the slot.
 *
 * @param  slotID  [in]  Id of slot to query.
 * @param  pInfo   [in]  Slot information copied into it.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SLOT_ID_INVALID when no slot with id can be found.
 *          CKR_ARGUMENTS_BAD when pInfo is NULL.
 *          CKR_OK on success.
 */
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!WP11_SlotIdValid(slotID))
        return CKR_SLOT_ID_INVALID;
    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    XMEMCPY(pInfo, &slotInfoTemplate, sizeof(slotInfoTemplate));
    /* Put in the slot id value as two decimal digits. */
    pInfo->slotDescription[SLOT_ID_IDX + 0] = ((slotID / 10) % 10) + '0';
    pInfo->slotDescription[SLOT_ID_IDX + 1] = ((slotID     ) % 10) + '0';

    return CKR_OK;
}

static CK_RV checkPinLen(CK_ULONG pinLen)
{
#if (WP11_MIN_PIN_LEN > 0)
    if (pinLen > WP11_MAX_PIN_LEN || pinLen < WP11_MIN_PIN_LEN)
#else
    if (pinLen > WP11_MAX_PIN_LEN)
#endif
        return CKR_PIN_INCORRECT;
    return CKR_OK;
}

/* Template for token information. */
static CK_TOKEN_INFO tokenInfoTemplate = {
    "",
    "wolfpkcs11",
    "wolfpkcs11",
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }, /* serialNumber */
    CKF_RNG | CKF_CLOCK_ON_TOKEN | CKF_LOGIN_REQUIRED,
    WP11_SESSION_CNT_MAX, /* ulMaxSessionCount */
    CK_UNAVAILABLE_INFORMATION, /* ulSessionCount */
    WP11_SESSION_CNT_MAX, /* ulMaxRwSessionCount */
    CK_UNAVAILABLE_INFORMATION, /* ulRwSessionCount */
    WP11_MAX_PIN_LEN, /* ulMaxPinLen */
    WP11_MIN_PIN_LEN, /* ulMinPinLen */
    CK_UNAVAILABLE_INFORMATION, /* ulTotalPublicMemory */
    CK_UNAVAILABLE_INFORMATION, /* ulFreePublicMemory */
    CK_UNAVAILABLE_INFORMATION, /* ulTotalPrivateMemory */
    CK_UNAVAILABLE_INFORMATION, /* ulFreePrivateMemory */
    { WOLFPKCS11_MAJOR_VERSION, WOLFPKCS11_MINOR_VERSION },
    { WOLFPKCS11_MAJOR_VERSION, WOLFPKCS11_MINOR_VERSION },
    {
        'Y', 'Y', 'Y', 'Y', 'M', 'M', 'D', 'D', 'h', 'h', 'm', 'm', 's', 's',
        '0', '0'
    }
};

/**
 * Get information on the token.
 *
 * @param  slotID  [in]  Id of slot to use.
 * @param  pInfo   [in]  Token information copied into it.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SLOT_ID_INVALID when no slot with id can be found.
 *          CKR_ARGUMENTS_BAD when pInfo is NULL.
 *          CKR_OK on success.
 */
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
#ifndef WOLFPKCS11_NO_TIME
    time_t now, expire;
    struct tm nowTM;
#endif
    WP11_Slot* slot;
    int cnt;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Slot_Get(slotID, &slot) != 0)
        return CKR_SLOT_ID_INVALID;
    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    XMEMCPY(pInfo, &tokenInfoTemplate, sizeof(tokenInfoTemplate));
    WP11_Slot_GetTokenLabel(slot, (char*)pInfo->label);
    pInfo->serialNumber[14] = ((slotID / 10) % 10) + '0';
    pInfo->serialNumber[15] = ((slotID /  1) % 10) + '0';
    if (WP11_Slot_Has_Empty_Pin(slot) ||
        !WP11_Slot_IsTokenUserPinInitialized(slot)) {
        pInfo->flags &= ~(CKF_LOGIN_REQUIRED);
    }

#ifndef WOLFPKCS11_NO_TIME
    now = XTIME(0);
    XMEMSET(&nowTM, 0, sizeof(nowTM));
    if (XGMTIME(&now, &nowTM) != NULL) {
        pInfo->utcTime[ 0] = (((1900 + nowTM.tm_year) / 1000) % 10) + '0';
        pInfo->utcTime[ 1] = (((1900 + nowTM.tm_year) /  100) % 10) + '0';
        pInfo->utcTime[ 2] = (((1900 + nowTM.tm_year) /   10) % 10) + '0';
        pInfo->utcTime[ 3] = (((1900 + nowTM.tm_year) /    1) % 10) + '0';
        pInfo->utcTime[ 4] = (((1 + nowTM.tm_mon) / 10) % 10) + '0';
        pInfo->utcTime[ 5] = (((1 + nowTM.tm_mon) /  1) % 10) + '0';
        pInfo->utcTime[ 6] = ((nowTM.tm_mday / 10) % 10) + '0';
        pInfo->utcTime[ 7] = ((nowTM.tm_mday /  1) % 10) + '0';
        pInfo->utcTime[ 8] = ((nowTM.tm_hour / 10) % 10) + '0';
        pInfo->utcTime[ 9] = ((nowTM.tm_hour /  1) % 10) + '0';
        pInfo->utcTime[10] = ((nowTM.tm_min / 10) % 10) + '0';
        pInfo->utcTime[11] = ((nowTM.tm_min /  1) % 10) + '0';
        pInfo->utcTime[12] = ((nowTM.tm_sec / 10) % 10) + '0';
        pInfo->utcTime[13] = ((nowTM.tm_sec /  1) % 10) + '0';
    }
    else {
        /* Set date to all zeros. */
        XMEMCPY(pInfo->utcTime, "00000000000000", 14);
    }
#else
    XMEMCPY(pInfo->utcTime, "00000000000000", 14);
#endif

    cnt = WP11_Slot_TokenFailedLogin(slot, WP11_LOGIN_SO);
#ifndef WOLFPKCS11_NO_TIME
    expire = WP11_Slot_TokenFailedExpire(slot, WP11_LOGIN_SO);
#endif
    if (cnt > 0)
        pInfo->flags |= CKF_SO_PIN_COUNT_LOW;
    if (cnt == WP11_MAX_LOGIN_FAILS_SO - 1)
        pInfo->flags |= CKF_SO_PIN_FINAL_TRY;
#ifndef WOLFPKCS11_NO_TIME
    else if (cnt == WP11_MAX_LOGIN_FAILS_SO && now < expire)
        pInfo->flags |= CKF_SO_PIN_LOCKED;
#endif

    cnt = WP11_Slot_TokenFailedLogin(slot, WP11_LOGIN_USER);
#ifndef WOLFPKCS11_NO_TIME
    expire = WP11_Slot_TokenFailedExpire(slot, WP11_LOGIN_USER);
#endif
    if (cnt > 0)
        pInfo->flags |= CKF_USER_PIN_COUNT_LOW;
    if (cnt == WP11_MAX_LOGIN_FAILS_USER - 1)
        pInfo->flags |= CKF_USER_PIN_FINAL_TRY;
#ifndef WOLFPKCS11_NO_TIME
    else if (cnt == WP11_MAX_LOGIN_FAILS_USER && now < expire)
        pInfo->flags |= CKF_USER_PIN_LOCKED;
#endif

    if (WP11_Slot_IsTokenInitialized(slot))
        pInfo->flags |= CKF_TOKEN_INITIALIZED;
    if (WP11_Slot_IsTokenUserPinInitialized(slot))
        pInfo->flags |= CKF_USER_PIN_INITIALIZED;

    return CKR_OK;
}

/* List of mechanism supported. */
static CK_MECHANISM_TYPE mechanismList[] = {
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
    CKM_RSA_PKCS_KEY_PAIR_GEN,
#endif
    CKM_RSA_X_509,
    CKM_RSA_PKCS,
#ifdef WOLFSSL_SHA224
    CKM_SHA224_RSA_PKCS,
#endif
#ifndef NO_SHA256
    CKM_SHA256_RSA_PKCS,
#endif
#ifdef WOLFSSL_SHA384
    CKM_SHA384_RSA_PKCS,
#endif
#ifdef WOLFSSL_SHA512
    CKM_SHA512_RSA_PKCS,
#endif
#ifndef WC_NO_RSA_OAEP
    CKM_RSA_PKCS_OAEP,
#endif
#ifdef WC_RSA_PSS
    CKM_RSA_PKCS_PSS,
#ifdef WOLFSSL_SHA224
    CKM_SHA224_RSA_PKCS_PSS,
#endif
#ifndef NO_SHA256
    CKM_SHA256_RSA_PKCS_PSS,
#endif
#ifdef WOLFSSL_SHA384
    CKM_SHA384_RSA_PKCS_PSS,
#endif
#ifdef WOLFSSL_SHA512
    CKM_SHA512_RSA_PKCS_PSS,
#endif
#endif
#endif
#ifdef HAVE_ECC
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
#ifndef NO_SHA
    CKM_ECDSA_SHA1,
#endif
#ifdef WOLFSSL_SHA224
    CKM_ECDSA_SHA224,
#endif
#ifndef NO_SHA256
    CKM_ECDSA_SHA256,
#endif
#ifdef WOLFSSL_SHA384
    CKM_ECDSA_SHA384,
#endif
#ifdef WOLFSSL_SHA512
    CKM_ECDSA_SHA512,
#endif
    CKM_ECDH1_DERIVE,
#endif
#ifdef WOLFPKCS11_HKDF
    CKM_HKDF_DERIVE,
    CKM_HKDF_DATA,
#endif
#ifndef NO_DH
    CKM_DH_PKCS_KEY_PAIR_GEN,
    CKM_DH_PKCS_DERIVE,
#endif
#ifndef NO_AES
    CKM_AES_KEY_GEN,
#ifdef HAVE_AES_KEY_WRAP
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_PAD,
#endif
#ifdef HAVE_AES_CBC
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
    CKM_AES_CBC_ENCRYPT_DATA,
#endif
#ifdef HAVE_AESCTR
    CKM_AES_CTR,
#endif
#ifdef HAVE_AESGCM
    CKM_AES_GCM,
#endif
#ifdef HAVE_AESCCM
    CKM_AES_CCM,
#endif
#ifdef HAVE_AESECB
    CKM_AES_ECB,
#endif
#ifdef HAVE_AESCTS
    CKM_AES_CTS,
#endif
#ifdef HAVE_AESCMAC
    CKM_AES_CMAC,
    CKM_AES_CMAC_GENERAL,
#endif
#endif
#ifndef NO_HMAC
#ifndef NO_MD5
    CKM_MD5_HMAC,
    CKM_MD5,
#endif
#ifndef NO_SHA
    CKM_SHA1_HMAC,
    CKM_SHA1,
#endif
#ifdef WOLFSSL_SHA224
    CKM_SHA224_HMAC,
    CKM_SHA224,
#endif
#ifndef NO_SHA256
    CKM_SHA256_HMAC,
    CKM_SHA256,
#endif
#ifdef WOLFSSL_SHA384
    CKM_SHA384_HMAC,
    CKM_SHA384,
#endif
#ifdef WOLFSSL_SHA512
    CKM_SHA512_HMAC,
    CKM_SHA512,
#endif
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
    CKM_SHA3_224_HMAC,
    CKM_SHA3_224,
#endif
#ifndef WOLFSSL_NOSHA3_256
    CKM_SHA3_256_HMAC,
    CKM_SHA3_256,
#endif
#ifndef WOLFSSL_NOSHA3_384
    CKM_SHA3_384_HMAC,
    CKM_SHA3_384,
#endif
#ifndef WOLFSSL_NOSHA3_512
    CKM_SHA3_512_HMAC,
    CKM_SHA3_512,
#endif
#endif
#endif
#ifndef NO_KDF
    CKM_TLS12_KEY_AND_MAC_DERIVE,
    CKM_TLS12_MASTER_KEY_DERIVE,
    CKM_TLS12_MASTER_KEY_DERIVE_DH,
#ifdef WOLFPKCS11_NSS
    CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE,
    CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH,
#endif
#endif
#ifdef WOLFPKCS11_NSS
    /* Only advertise CKM_SSL3_MASTER_KEY_DERIVE. Not implemented. */
    CKM_SSL3_MASTER_KEY_DERIVE,
#endif
#ifdef WOLFSSL_HAVE_PRF
    CKM_TLS_MAC,
#endif
    CKM_GENERIC_SECRET_KEY_GEN,
};

/* Count of mechanisms in list. */
static int mechanismCnt = ((int)(sizeof(mechanismList)/sizeof(*mechanismList)));

/**
 * Get list of supported mechanisms for the slot.
 *
 * @param  slotID           [in]      Id of slot to use.
 * @param  pMechanismList   [in]      Array to hold mechanisms.
 *                                    NULL indicates the length is required.
 * @param  pulCount         [in,out]  On in, the number of array entries in
 *                                    pMechanismList.
 *                                    On out, the number of mechanisms put in
 *                                    array.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SLOT_ID_INVALID when no slot with id can be found.
 *          CKR_ARGUMENTS_BAD when pulCount is NULL.
 *          CKR_BUFFER_TOO_SMALL when pulCount is NULL.
 *          CKR_BUFFER_TOO_SMALL when there are more mechanisms than entries in
 *          array.
 *          CKR_OK on success.
 */
CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                         CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount)
{
    int i;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!WP11_SlotIdValid(slotID))
        return CKR_SLOT_ID_INVALID;
    if (pulCount == NULL)
        return CKR_ARGUMENTS_BAD;

    if (pMechanismList == NULL)
        *pulCount = mechanismCnt;
    else if (*pulCount < (CK_ULONG)mechanismCnt)
        return CKR_BUFFER_TOO_SMALL;
    else {
        for (i = 0; i < mechanismCnt; i++)
            pMechanismList[i] = mechanismList[i];
        *pulCount = mechanismCnt;
    }

    return CKR_OK;
}

#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
/* Info on RSA key generation mechanism. */
static CK_MECHANISM_INFO rsaKgMechInfo = {
    1024, 4096, CKF_GENERATE_KEY_PAIR
};
#endif
/* Info on RSA X.509 mechanism. */
static CK_MECHANISM_INFO rsaX509MechInfo = {
    1024, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP | CKF_UNWRAP
};
/* Info on RSA PKCS#1.5 mechanism. */
static CK_MECHANISM_INFO rsaPkcsMechInfo = {
    1024, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY
};
#ifndef WC_NO_RSA_OAEP
/* Info on RSA PKCS#1 OAEP mechanism. */
static CK_MECHANISM_INFO rsaOaepMechInfo = {
    1024, 4096, CKF_ENCRYPT | CKF_DECRYPT
};
#endif
#ifdef WC_RSA_PSS
/* Info on RSA PKCS#1 PSS mechanism. */
static CK_MECHANISM_INFO rsaPssMechInfo = {
    256, 521, CKF_SIGN | CKF_VERIFY
};
#endif
#ifndef NO_SHA256
static CK_MECHANISM_INFO shaRsaPkcsMechInfo = {
    1024, 4096, CKF_SIGN | CKF_VERIFY
};
#endif
#endif
#ifdef HAVE_ECC
/* Info on EC key generation mechanism. */
static CK_MECHANISM_INFO ecKgMechInfo = {
    256, 521, CKF_GENERATE_KEY_PAIR
};
/* Info on ECDSA mechanism. */
static CK_MECHANISM_INFO ecdsaMechInfo = {
    256, 521, CKF_SIGN | CKF_VERIFY
};
#ifndef NO_SHA
static CK_MECHANISM_INFO ecdsaSha1MechInfo = {
    256, 521, CKF_SIGN | CKF_VERIFY
};
#endif
#ifdef WOLFSSL_SHA224
static CK_MECHANISM_INFO ecdsaSha224MechInfo = {
    256, 521, CKF_SIGN | CKF_VERIFY
};
#endif
#ifndef NO_SHA256
static CK_MECHANISM_INFO ecdsaSha256MechInfo = {
    256, 521, CKF_SIGN | CKF_VERIFY
};
#endif
#ifdef WOLFSSL_SHA384
static CK_MECHANISM_INFO ecdsaSha384MechInfo = {
    256, 521, CKF_SIGN | CKF_VERIFY
};
#endif
#ifdef WOLFSSL_SHA512
static CK_MECHANISM_INFO ecdsaSha512MechInfo = {
    256, 521, CKF_SIGN | CKF_VERIFY
};
#endif
/* Info on ECDH mechanism. */
static CK_MECHANISM_INFO ecdhMechInfo = {
    256, 521, CKF_DERIVE
};
#endif
#ifdef WOLFPKCS11_HKDF
static CK_MECHANISM_INFO hkdfMechInfo = {
    1, 16320, CKF_DERIVE
};
static CK_MECHANISM_INFO hkdfDatMechInfo = {
    1, 16320, CKF_DERIVE
};
#endif
#ifndef NO_DH
/* Info on DH key generation mechanism. */
static CK_MECHANISM_INFO dhKgMechInfo = {
    1024, 4096, CKF_GENERATE_KEY_PAIR
};
/* Info on DH key derivation mechanism. */
static CK_MECHANISM_INFO dhPkcsMechInfo = {
    1024, 4096, CKF_DERIVE
};
#endif
#ifndef NO_KDF
static CK_MECHANISM_INFO tls12MasterKeyDeriveDhInfo = {
    8, 128, CKF_DERIVE
};
static CK_MECHANISM_INFO tls12MasterKeyDeriveInfo = {
    48, 48, CKF_DERIVE
};
static CK_MECHANISM_INFO tls12KeyAndMacDeriveInfo = {
    48, 48, CKF_DERIVE
};
#ifdef WOLFPKCS11_NSS
static CK_MECHANISM_INFO nssTls12MasterKeyDeriveDhInfo = {
    48, 128, CKF_DERIVE
};
static CK_MECHANISM_INFO nssTls12MasterKeyDeriveInfo = {
    48, 128, CKF_DERIVE
};
#endif
#endif
#ifdef WOLFPKCS11_NSS
static CK_MECHANISM_INFO ssl3MasterKeyDeriveInfo = {
    48, 48, CKF_DERIVE
};
#endif
static CK_MECHANISM_INFO tlsMacMechInfo = {
    0, 512, CKF_SIGN | CKF_VERIFY
};
#ifndef NO_AES
static CK_MECHANISM_INFO aesKeyGenMechInfo = {
    16, 32, CKF_GENERATE
};
#ifdef HAVE_AES_KEY_WRAP
static CK_MECHANISM_INFO aesKeyWrapMechInfo = {
    16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP
};
#endif
#ifdef HAVE_AES_CBC
/* Info on AES-CBC mechanism. */
static CK_MECHANISM_INFO aesCbcMechInfo = {
    16, 32, CKF_ENCRYPT | CKF_DECRYPT
};
static CK_MECHANISM_INFO aesCbcEncryptDataMechInfo = {
    1, 32, CKF_DERIVE
};
#endif
#ifdef HAVE_AESCTR
/* Info on AES-CTR mechanism. */
static CK_MECHANISM_INFO aesCtrMechInfo = {
    16, 32, CKF_ENCRYPT | CKF_DECRYPT
};
#endif
#ifdef HAVE_AESGCM
/* Info on AES-GCM mechanism. */
static CK_MECHANISM_INFO aesGcmMechInfo = {
    16, 32, CKF_ENCRYPT | CKF_DECRYPT
};
#endif
#ifdef HAVE_AESCCM
/* Info on AES-CCM mechanism. */
static CK_MECHANISM_INFO aesCcmMechInfo = {
    16, 32, CKF_ENCRYPT | CKF_DECRYPT
};
#endif
#ifdef HAVE_AESECB
/* Info on AES-ECB mechanism. */
static CK_MECHANISM_INFO aesEcbMechInfo = {
    16, 32, CKF_ENCRYPT | CKF_DECRYPT
};
#endif
#ifdef HAVE_AESCTS
/* Info on AES-CTS mechanism. */
static CK_MECHANISM_INFO aesCtsMechInfo = {
    16, 32, CKF_ENCRYPT | CKF_DECRYPT
};
#endif
#ifdef HAVE_AESCMAC
static CK_MECHANISM_INFO aesCbcSigVerMechInfo = {
    16, 32, CKF_SIGN | CKF_VERIFY
};
#endif
#endif
#ifndef NO_HMAC
#ifndef NO_MD5
/* Info on HMAC-MD5 mechanism. */
static CK_MECHANISM_INFO hmacMd5MechInfo = {
    16, 512, CKF_SIGN | CKF_VERIFY
};
static CK_MECHANISM_INFO md5MechInfo = {
    0, 0, CKF_DIGEST
};
#endif
#ifndef NO_SHA
/* Info on HMAC-SHA1 mechanism. */
static CK_MECHANISM_INFO hmacSha1MechInfo = {
    20, 512, CKF_SIGN | CKF_VERIFY
};
static CK_MECHANISM_INFO sha1MechInfo = {
    0, 0, CKF_DIGEST
};
#endif
#ifdef WOLFSSL_SHA224
/* Info on HMAC-SHA224 mechanism. */
static CK_MECHANISM_INFO hmacSha224MechInfo = {
    28, 512, CKF_SIGN | CKF_VERIFY
};
static CK_MECHANISM_INFO sha224MechInfo = {
    0, 0, CKF_DIGEST
};
#endif
#ifndef NO_SHA256
/* Info on HMAC-SHA256 mechanism. */
static CK_MECHANISM_INFO hmacSha256MechInfo = {
    32, 512, CKF_SIGN | CKF_VERIFY
};
static CK_MECHANISM_INFO sha256MechInfo = {
    0, 0, CKF_DIGEST
};
#endif
#ifdef WOLFSSL_SHA384
/* Info on HMAC-SHA384 mechanism. */
static CK_MECHANISM_INFO hmacSha384MechInfo = {
    48, 512, CKF_SIGN | CKF_VERIFY
};
static CK_MECHANISM_INFO sha384MechInfo = {
    0, 0, CKF_DIGEST
};
#endif
#ifdef WOLFSSL_SHA512
/* Info on HMAC-SHA512 mechanism. */
static CK_MECHANISM_INFO hmacSha512MechInfo = {
    64, 512, CKF_SIGN | CKF_VERIFY
};
static CK_MECHANISM_INFO sha512MechInfo = {
    0, 0, CKF_DIGEST
};
#endif
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
static CK_MECHANISM_INFO hmacSha3224MechInfo = {
    28, 512, CKF_SIGN | CKF_VERIFY
};
#endif
#ifndef WOLFSSL_NOSHA3_256
static CK_MECHANISM_INFO hmacSha3256MechInfo = {
    32, 512, CKF_SIGN | CKF_VERIFY
};
#endif
#ifndef WOLFSSL_NOSHA3_384
static CK_MECHANISM_INFO hmacSha3384MechInfo = {
    48, 512, CKF_SIGN | CKF_VERIFY
};
#endif
#ifndef WOLFSSL_NOSHA3_512
static CK_MECHANISM_INFO hmacSha3512MechInfo = {
    64, 512, CKF_SIGN | CKF_VERIFY
};
#endif
static CK_MECHANISM_INFO sha3MechInfo = {
    0, 0, CKF_DIGEST
};
#endif
#endif
static CK_MECHANISM_INFO genSecKeyGenMechInfo = {
    1, 32, CKF_GENERATE
};

/**
 * Get information on a mechanism.
 *
 * @param  slotID  [in]  Id of slot to use.
 * @param  type    [in]  Mechanism type.
 * @param  pInfo   [in]  Mechanism information copied into it.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SLOT_ID_INVALID when no slot with id can be found.
 *          CKR_ARGUMENTS_BAD when pInfo is NULL.
 *          CKR_MECHANISM_INVALID when mechanism is not supported.
 *          CKR_OK on success.
 */
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo)
{
    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!WP11_SlotIdValid(slotID))
        return CKR_SLOT_ID_INVALID;
    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    switch (type) {
#ifndef NO_RSA
    #ifdef WOLFSSL_KEY_GEN
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            XMEMCPY(pInfo, &rsaKgMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
    #endif
        case CKM_RSA_X_509:
            XMEMCPY(pInfo, &rsaX509MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_RSA_PKCS:
            XMEMCPY(pInfo, &rsaPkcsMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
    #ifndef WC_NO_RSA_OAEP
        case CKM_RSA_PKCS_OAEP:
            XMEMCPY(pInfo, &rsaOaepMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_RSA_PKCS:
    #endif
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_RSA_PKCS:
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_RSA_PKCS:
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_RSA_PKCS:
    #endif
            XMEMCPY(pInfo, &shaRsaPkcsMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
    #ifdef WC_RSA_PSS
        case CKM_RSA_PKCS_PSS:
            XMEMCPY(pInfo, &rsaPssMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        #ifndef NO_SHA256
        case CKM_SHA256_RSA_PKCS_PSS:
        #endif
        #ifdef WOLFSSL_SHA224
        case CKM_SHA224_RSA_PKCS_PSS:
        #endif
        #ifdef WOLFSSL_SHA384
        case CKM_SHA384_RSA_PKCS_PSS:
        #endif
        #ifdef WOLFSSL_SHA512
        case CKM_SHA512_RSA_PKCS_PSS:
        #endif
            XMEMCPY(pInfo, &shaRsaPkcsMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
    #endif
#endif
#ifdef HAVE_ECC
        case CKM_EC_KEY_PAIR_GEN:
            XMEMCPY(pInfo, &ecKgMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_ECDSA:
            XMEMCPY(pInfo, &ecdsaMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#ifndef NO_SHA
        case CKM_ECDSA_SHA1:
            XMEMCPY(pInfo, &ecdsaSha1MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_SHA224
        case CKM_ECDSA_SHA224:
            XMEMCPY(pInfo, &ecdsaSha224MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef NO_SHA256
        case CKM_ECDSA_SHA256:
            XMEMCPY(pInfo, &ecdsaSha256MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_SHA384
        case CKM_ECDSA_SHA384:
            XMEMCPY(pInfo, &ecdsaSha384MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_SHA512
        case CKM_ECDSA_SHA512:
            XMEMCPY(pInfo, &ecdsaSha512MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
        case CKM_ECDH1_DERIVE:
            XMEMCPY(pInfo, &ecdhMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFPKCS11_HKDF
        case CKM_HKDF_DERIVE:
            XMEMCPY(pInfo, &hkdfMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_HKDF_DATA:
            XMEMCPY(pInfo, &hkdfDatMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef NO_DH
        case CKM_DH_PKCS_KEY_PAIR_GEN:
            XMEMCPY(pInfo, &dhKgMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_DH_PKCS_DERIVE:
            XMEMCPY(pInfo, &dhPkcsMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef NO_AES
        case CKM_AES_KEY_GEN:
            XMEMCPY(pInfo, &aesKeyGenMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#ifdef HAVE_AES_KEY_WRAP
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_PAD:
            XMEMCPY(pInfo, &aesKeyWrapMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef HAVE_AES_CBC
        case CKM_AES_CBC_PAD:
        case CKM_AES_CBC:
            XMEMCPY(pInfo, &aesCbcMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_AES_CBC_ENCRYPT_DATA:
            XMEMCPY(pInfo, &aesCbcEncryptDataMechInfo,
                    sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef HAVE_AESCTR
        case CKM_AES_CTR:
            XMEMCPY(pInfo, &aesCtrMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef HAVE_AESGCM
        case CKM_AES_GCM:
            XMEMCPY(pInfo, &aesGcmMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef HAVE_AESCCM
        case CKM_AES_CCM:
            XMEMCPY(pInfo, &aesCcmMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef HAVE_AESECB
        case CKM_AES_ECB:
            XMEMCPY(pInfo, &aesEcbMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef HAVE_AESCTS
        case CKM_AES_CTS:
            XMEMCPY(pInfo, &aesCtsMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef HAVE_AESCMAC
        case CKM_AES_CMAC:
        case CKM_AES_CMAC_GENERAL:
            XMEMCPY(pInfo, &aesCbcSigVerMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#endif
#ifndef NO_HMAC
#ifndef NO_MD5
        case CKM_MD5_HMAC:
            XMEMCPY(pInfo, &hmacMd5MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_MD5:
            XMEMCPY(pInfo, &md5MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef NO_SHA
        case CKM_SHA1_HMAC:
            XMEMCPY(pInfo, &hmacSha1MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_SHA1:
            XMEMCPY(pInfo, &sha1MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_SHA224
        case CKM_SHA224_HMAC:
            XMEMCPY(pInfo, &hmacSha224MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_SHA224:
            XMEMCPY(pInfo, &sha224MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef NO_SHA256
        case CKM_SHA256_HMAC:
            XMEMCPY(pInfo, &hmacSha256MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_SHA256:
            XMEMCPY(pInfo, &sha256MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_SHA384
        case CKM_SHA384_HMAC:
            XMEMCPY(pInfo, &hmacSha384MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_SHA384:
            XMEMCPY(pInfo, &sha384MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_SHA512
        case CKM_SHA512_HMAC:
            XMEMCPY(pInfo, &hmacSha512MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_SHA512:
            XMEMCPY(pInfo, &sha512MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224_HMAC:
            XMEMCPY(pInfo, &hmacSha3224MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256_HMAC:
            XMEMCPY(pInfo, &hmacSha3256MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384_HMAC:
            XMEMCPY(pInfo, &hmacSha3384MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512_HMAC:
            XMEMCPY(pInfo, &hmacSha3512MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224:
#endif
#ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256:
#endif
#ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384:
#endif
#ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512:
#endif
            XMEMCPY(pInfo, &sha3MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#endif
#ifndef NO_KDF
        case CKM_TLS12_KEY_AND_MAC_DERIVE:
            XMEMCPY(pInfo, &tls12KeyAndMacDeriveInfo,
                    sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_TLS12_MASTER_KEY_DERIVE:
            XMEMCPY(pInfo, &tls12MasterKeyDeriveInfo,
                    sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_TLS12_MASTER_KEY_DERIVE_DH:
            XMEMCPY(pInfo, &tls12MasterKeyDeriveDhInfo,
                    sizeof(CK_MECHANISM_INFO));
            break;
#ifdef WOLFPKCS11_NSS
        case CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE:
            XMEMCPY(pInfo, &nssTls12MasterKeyDeriveInfo,
                    sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH:
            XMEMCPY(pInfo, &nssTls12MasterKeyDeriveDhInfo,
                    sizeof(CK_MECHANISM_INFO));
            break;
#endif
#endif
#ifdef WOLFPKCS11_NSS
        /* Only advertise CKM_SSL3_MASTER_KEY_DERIVE. Not implemented. */
        case CKM_SSL3_MASTER_KEY_DERIVE:
            XMEMCPY(pInfo, &ssl3MasterKeyDeriveInfo,
                    sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_HAVE_PRF
        case CKM_TLS_MAC:
            XMEMCPY(pInfo, &tlsMacMechInfo,
                    sizeof(CK_MECHANISM_INFO));
            break;
#endif
        case CKM_GENERIC_SECRET_KEY_GEN:
            XMEMCPY(pInfo, &genSecKeyGenMechInfo,
                    sizeof(CK_MECHANISM_INFO));
            break;
        default:
            return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/**
 * Initialize or re-initialize token in slot.
 *
 * @param  slotId    [in]  Id of slot to use.
 * @param  pPin      [in]  PIN for Security Officer (SO).
 * @param  ulPinLen  [in]  Length of PIN in bytes.
 * @param  pLabel    [in]  Label for token.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SLOT_ID_INVALID when no slot with id can be found.
 *          CKR_ARGUMENTS_BAD when pPin or pLabel is NULL.
 *          CKR_PIN_INCORRECT when length of PIN is not valid or PIN does not
 *          match initialized PIN.
 *          CKR_SESSION_EXISTS when a session is open on the token.
 *          CKR_FUNCTION_FAILED when resetting token fails.
 *          CKR_OK on success.
 */
CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
                  CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    int ret;
    WP11_Slot* slot;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Slot_Get(slotID, &slot) != 0)
        return CKR_SLOT_ID_INVALID;
    if (pPin == NULL || pLabel == NULL)
        return CKR_ARGUMENTS_BAD;

    if (checkPinLen(ulPinLen) != CKR_OK)
        return CKR_PIN_INCORRECT;

    if (WP11_Slot_IsTokenInitialized(slot)) {
        if (WP11_Slot_HasSession(slot))
            return CKR_SESSION_EXISTS;
        if (WP11_Slot_SOPin_IsSet(slot)) {
            ret = WP11_Slot_CheckSOPin(slot, (char*)pPin, (int)ulPinLen);
            if (ret != 0)
                return CKR_PIN_INCORRECT;
        }
    }

    ret = WP11_Slot_TokenReset(slot, (char*)pPin, (int)ulPinLen, (char*)pLabel);
    if (ret != 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}

/**
 * Initialize User PIN.
 *
 * @param  hSession  [in]  Session handle.
 * @param  pPin      [in]  PIN to set for User.
 * @param  ulPinLen  [in]  Length of PIN in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pPin is NULL.
 *          CKR_USER_NOT_LOGGED_IN when not logged in as Security Officer.
 *          CKR_PIN_INCORRECT when length of PIN is not valid.
 *          CKR_FUNCTION_FAILED when setting User PIN fails.
 *          CKR_OK on success.
 */
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                CK_ULONG ulPinLen)
{
    int ret;
    WP11_Slot* slot;
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pPin == NULL && ulPinLen > 0)
        return CKR_ARGUMENTS_BAD;
    if (WP11_Session_GetState(session) != WP11_APP_STATE_RW_SO)
        return CKR_USER_NOT_LOGGED_IN;

    if (checkPinLen(ulPinLen) != CKR_OK)
        return CKR_PIN_INCORRECT;

    slot = WP11_Session_GetSlot(session);
    ret = WP11_Slot_SetUserPin(slot, (char*)pPin, (int)ulPinLen);
    if (ret != 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}

/**
 * Change the PIN of the currently logged in user.
 *
 * @param  hSession     [in]  Session handle.
 * @param  pOldPin      [in]  Old PIN of user.
 * @param  ulOldPinLen  [in]  Length of old PIN in bytes.
 * @param  pNewPin      [in]  New PIN to set for user.
 * @param  ulNewPinLen  [in]  Length of new PIN in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pOldPin or pNewPin is NULL.
 *          CKR_PIN_INCORRECT when length of old or new PIN is not valid or
 *          old PIN does not verify.
 *          CKR_SESSION_READ_ONLY when session not read/write.
 *          CKR_USER_PIN_NOT_INITIALIZED when no previous PIN set for user.
 *          CKR_FUNCTION_FAILED when setting user PIN fails.
 *          CKR_OK on success.
 */
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
               CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,
               CK_ULONG ulNewLen)
{
    int ret;
    int state;
    WP11_Slot* slot;
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pOldPin == NULL || pNewPin == NULL)
        return CKR_ARGUMENTS_BAD;
    if (checkPinLen(ulOldLen) != CKR_OK)
        return CKR_PIN_INCORRECT;
    if (checkPinLen(ulNewLen) != CKR_OK)
        return CKR_PIN_INCORRECT;

    state = WP11_Session_GetState(session);
    if (state != WP11_APP_STATE_RW_SO && state != WP11_APP_STATE_RW_USER &&
                                            state != WP11_APP_STATE_RW_PUBLIC) {
        return CKR_SESSION_READ_ONLY;
    }

    slot = WP11_Session_GetSlot(session);
    if (state == WP11_APP_STATE_RW_SO) {
        ret = WP11_Slot_CheckSOPin(slot, (char*)pOldPin, (int)ulOldLen);
        if (ret == PIN_NOT_SET_E)
            return CKR_USER_PIN_NOT_INITIALIZED;
        if (ret != 0)
            return CKR_PIN_INCORRECT;

        ret = WP11_Slot_SetSOPin(slot, (char*)pNewPin, (int)ulNewLen);
        if (ret != 0)
            return CKR_FUNCTION_FAILED;
    }
    else {
        ret = WP11_Slot_CheckUserPin(slot, (char*)pOldPin, (int)ulOldLen);
        if (ret == PIN_NOT_SET_E)
            return CKR_USER_PIN_NOT_INITIALIZED;
        if (ret != 0)
            return CKR_PIN_INCORRECT;

        ret = WP11_Slot_SetUserPin(slot, (char*)pNewPin, (int)ulNewLen);
        if (ret != 0)
            return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

/**
 * Open session on the token.
 *
 * @param  slotID        [in]  Id of slot to use.
 * @param  flags         [in]  Flags to indicate type of session to open.
 *                             CKF_SERIAL_SESSION must be set.
 * @param  pApplication  [in]  Application data to pass to notify callback.
 *                             Ignored.
 * @param  Notify        [in]  Notification callback.
 *                             Ignored.
 * @param  phsession     [in]  Session handle of opened session.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SLOT_ID_INVALID when no slot with id can be found.
 *          CKR_SESSION_PARALLEL_NOT_SUPPORTED when CKF_SERIAL_SESSION is not
 *          set in the flags.
 *          CKR_ARGUMENTS_BAD when phSession is NULL.
 *          CKR_SESSION_READ_WRITE_SO_EXISTS when there is an existing open
 *          Security Officer session.
 *          CKR_SESSION_COUNT when no more sessions can be opened on token.
 *          CKR_OK on success.
 */
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                    CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                    CK_SESSION_HANDLE_PTR phSession)
{
    WP11_Slot* slot;
    int ret;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Slot_Get(slotID, &slot) != 0)
        return CKR_SLOT_ID_INVALID;
    if ((flags & CKF_SERIAL_SESSION) == 0)
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    if (phSession == NULL)
        return CKR_ARGUMENTS_BAD;

    ret = WP11_Slot_OpenSession(slot, flags, pApplication, Notify, phSession);
    if (ret == SESSION_EXISTS_E)
        return CKR_SESSION_READ_WRITE_SO_EXISTS;
    if (ret == SESSION_COUNT_E)
        return CKR_SESSION_COUNT;

    return CKR_OK;
}

/**
 * Close the session.
 *
 * @param  hSession  [in]  Session handle.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_OK on success.
 */
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    WP11_Slot* slot;
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;

    slot = WP11_Session_GetSlot(session);
    WP11_Slot_CloseSession(slot, session);

    return CKR_OK;
}

/**
 * Close all open sessions on token in slot.
 *
 * @param  slotID        [in]  Id of slot to use.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SLOT_ID_INVALID when no slot with id can be found.
 *          CKR_OK on success.
 */
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    WP11_Slot* slot;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Slot_Get(slotID, &slot) != 0)
        return CKR_SLOT_ID_INVALID;
    WP11_Slot_CloseSessions(slot);

    return CKR_OK;
}

/**
 * Get the session info.
 *
 * @param  hSession  [in]  Session handle.
 * @param  pInfo     [in]  Session information copies into it.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pInfo is NULL.
 *          CKR_OK on success.
 */
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                       CK_SESSION_INFO_PTR pInfo)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    pInfo->state = WP11_Session_GetState(session);
    pInfo->flags = CKF_SERIAL_SESSION;
    if (WP11_Session_IsRW(session))
        pInfo->flags |= CKF_RW_SESSION;
    pInfo->ulDeviceError = 0;

    return CKR_OK;
}

/**
 * Get the state of the current operation.
 * Only intended for Digest state.
 *
 * @param  hSession            [in]      Session handle.
 * @param  pOperationState     [in]      Buffer to hold operation state.
 *                                       NULL indicates the length is required.
 * @param  pOperationStateLen  [in,out]  On in, length of buffer in bytes.
 *                                       On out, length of serialized state in
 *                                       bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pulOperationStateLen is NULL.
 *          CKR_STATE_UNSAVEABLE indicating the state is not saveable.
 */
CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG_PTR pulOperationStateLen)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pulOperationStateLen == NULL)
        return CKR_ARGUMENTS_BAD;

    return WP11_GetOperationState(session, pOperationState,
        pulOperationStateLen);
}

/**
 * Get the state of the current operation.
 * Only intended for Digest state.
 *
 * @param  hSession             [in]  Session handle.
 * @param  pOperationState      [in]  Serialized state.
 * @param  ulOperationStateLen  [in]  Length of serialized state in bytes.
 * @param  hEncryptionKey       [in]  Object handle for encryption key.
 * @param  hAuthenticationKey   [in]  Object handle for authentication key.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pOperationState is NULL.
 *          CKR_SAVED_STATE_INVALID indicating the state is not valid.
 */
CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG ulOperationStateLen,
                          CK_OBJECT_HANDLE hEncryptionKey,
                          CK_OBJECT_HANDLE hAuthenticationKey)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pOperationState == NULL)
        return CKR_ARGUMENTS_BAD;

    (void)hEncryptionKey;
    (void)hAuthenticationKey;

    return WP11_SetOperationState(session, pOperationState,
        ulOperationStateLen);
}

/**
 * Log the specified user type into the session.
 *
 * @param  hSession  [in]  Session handle.
 * @param  userType  [in]  Type of user to login.
 * @param  pPin      [in]  PIN to use to login.
 * @param  ulPinLen  [in]  Length of PIN in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pPin is NULL.
 *          CKR_USER_ALREADY_LOGGED_IN when already logged into session.
 *          CKR_SESSION_READ_ONLY_EXISTS when logging into read/write session
 *          and a read-only session is open.
 *          CKR_USER_PIN_NOT_INITIALIZED when PIN is not initialized for user
 *          type.
 *          CKR_PIN_INCORRECT when PIN is wrong length or does not verify.
 *          CKR_OPERATION_NOT_INITIALIZED when using user type
 *          CKU_CONTEXT_SPECIFIC - user type not supported.
 *          CKR_USER_TYPE_INVALID when other user type is specified.
 *          CKR_OK on success.
 */
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    int ret;
    WP11_Slot* slot;
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pPin == NULL)
        return CKR_ARGUMENTS_BAD;

    if (checkPinLen(ulPinLen) != CKR_OK)
        return CKR_PIN_INCORRECT;

    slot = WP11_Session_GetSlot(session);
    if (userType == CKU_SO) {
        ret = WP11_Slot_SOLogin(slot, (char*)pPin, (int)ulPinLen);
        if (ret == LOGGED_IN_E)
            return CKR_USER_ALREADY_LOGGED_IN;
        if (ret == READ_ONLY_E)
            return CKR_SESSION_READ_ONLY_EXISTS;
        if (ret == PIN_NOT_SET_E)
            return CKR_USER_PIN_NOT_INITIALIZED;
        if (ret != 0)
            return CKR_PIN_INCORRECT;

    }
    else if (userType == CKU_USER) {
        ret = WP11_Slot_UserLogin(slot, (char*)pPin, (int)ulPinLen);
        if (ret == LOGGED_IN_E)
            return CKR_USER_ALREADY_LOGGED_IN;
        if (ret == PIN_NOT_SET_E)
            return CKR_USER_PIN_NOT_INITIALIZED;
        if (ret != 0)
            return CKR_PIN_INCORRECT;
    }
    else if (userType == CKU_CONTEXT_SPECIFIC)
        return CKR_OPERATION_NOT_INITIALIZED;
    else
        return CKR_USER_TYPE_INVALID;

    return CKR_OK;
}

/**
 * Log out the user from the session.
 *
 * @param  hSession  [in]  Session handle.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_OK on success.
 */
CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    WP11_Slot* slot;
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;

    slot = WP11_Session_GetSlot(session);
    WP11_Slot_Logout(slot);

    return CKR_OK;
}

/**
 * Get the status of the current cryptographic function.
 *
 * @param  hSession  [in]  Session handle.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_FUNCTION_NOT_PARALLEL indicating function not supported.
 */
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_FUNCTION_NOT_PARALLEL;
}

/**
 * Cancel the current cryptographic function.
 *
 * @param  hSession  [in]  Session handle.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_FUNCTION_NOT_PARALLEL indicating function not supported.
 */
CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_FUNCTION_NOT_PARALLEL;
}

/**
 * Wait for an event on any slot.
 *
 * @param  flags      [in]  Indicate whether to block.
 * @param  pSlot      [in]  Handle of slot that event occurred on.
 * @param  pReserved  [in]  Reserved for future use.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_FUNCTION_NOT_PARALLEL indicating function not supported.
 */
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
                         CK_VOID_PTR pReserved)
{
    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    (void)pSlot;
    (void)flags;
    (void)pReserved;

    return CKR_FUNCTION_NOT_SUPPORTED;
}
