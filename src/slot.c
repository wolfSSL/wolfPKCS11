#include "internal.h"

#include <wolfpkcs11/pkcs11.h>

/**
 * Get list of slots with a token attached.
 *
 * @param  tokenPresent  [in]      Only return slots with token present when
 *                                 true.
 * @param  pSlotList     [in]      Array to hold slot ids.
 *                                 NULL indicates the length is required.
 * @param  pulCount      [in,out]  On in, the number of array entries in
 *                                 pSlotList.
 *                                 On out, the number of slots put in array.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_ARGUMENTS_BAD when pulCount is NULL.
 *          CKR_BUFFER_TOO_SMALL when there are more slots than entries in
 *          array.
 *          CKR_OK on success.
 */
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount)
{
    int i;
    int cnt = 0;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pulCount == NULL)
        return CKR_ARGUMENTS_BAD;

    for (i = 0; i < WP11_SLOT_COUNT; i++) {
        if (!tokenPresent || WP11_Slot_IsTokenPresent(i))
            cnt++;
    }

    if (pSlotList == NULL)
        *pulCount = cnt;
    else if (*pulCount < (CK_ULONG)cnt)
        return CKR_BUFFER_TOO_SMALL;
    else {
        cnt = 0;
        for (i = 0; i < WP11_SLOT_COUNT; i++) {
            if (!tokenPresent || WP11_Slot_IsTokenPresent(i))
                pSlotList[cnt++] = i;
        }
        *pulCount = cnt;
    }

    return CKR_OK;
}

#define SLOT_ID_IDX(id)  ((int)(id))

/**
 * Get information about a slot.
 *
 * @param  slotID  [in]   Id of slot to use.
 * @param  pInfo   [out]  Slot information copied into it.
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

    XMEMSET(pInfo, 0, sizeof(*pInfo));
    XSTRNCPY((char*)pInfo->slotDescription, "wolfPKCS11 Slot",
                                                 sizeof(pInfo->slotDescription));
    XSTRNCPY((char*)pInfo->manufacturerID, "wolfSSL Inc.",
                                                 sizeof(pInfo->manufacturerID));
    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 0;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 0;
    pInfo->firmwareVersion.minor = 0;

    return CKR_OK;
}

/**
 * Get information about a token in a slot.
 *
 * @param  slotID  [in]   Id of slot to use.
 * @param  pInfo   [out]  Token information copied into it.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SLOT_ID_INVALID when no slot with id can be found.
 *          CKR_ARGUMENTS_BAD when pInfo is NULL.
 *          CKR_TOKEN_NOT_PRESENT when no token is in the slot.
 *          CKR_OK on success.
 */
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    WP11_Slot* slot;
    time_t now;
    time_t expire;
    int cnt;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Slot_Get(slotID, &slot) != 0)
        return CKR_SLOT_ID_INVALID;
    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;
    if (!WP11_Slot_IsTokenPresent(SLOT_ID_IDX(slotID)))
        return CKR_TOKEN_NOT_PRESENT;

    XMEMSET(pInfo, 0, sizeof(*pInfo));
    XSTRNCPY((char*)pInfo->label, WP11_Slot_GetTokenLabel(slot),
                                                         sizeof(pInfo->label));
    XSTRNCPY((char*)pInfo->manufacturerID, "wolfSSL Inc.",
                                                 sizeof(pInfo->manufacturerID));
    XSTRNCPY((char*)pInfo->model, "wolfPKCS11", sizeof(pInfo->model));
    XSTRNCPY((char*)pInfo->serialNumber, "1", sizeof(pInfo->serialNumber));
    pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED;
    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = WP11_Slot_GetSessionCount(slot);
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulRwSessionCount = WP11_Slot_GetRWSessionCount(slot);
    pInfo->ulMaxPinLen = WP11_MAX_PIN_LEN;
    pInfo->ulMinPinLen = WP11_MIN_PIN_LEN;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 0;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 0;
    pInfo->firmwareVersion.minor = 0;
    XSTRNCPY((char*)pInfo->utcTime, "0000000000000000",
                                                        sizeof(pInfo->utcTime));

    if (WP11_Slot_IsUserPinSet(slot))
        pInfo->flags |= CKF_USER_PIN_INITIALIZED;

#ifndef WOLFPKCS11_NO_TIME
    now = time(NULL);
    expire = WP11_Slot_TokenFailedLoginExpire(slot, WP11_LOGIN_SO);
#endif

    cnt = WP11_Slot_TokenFailedLogin(slot, WP11_LOGIN_SO);
    if (cnt == WP11_MAX_LOGIN_FAILS_SO - 1)
        pInfo->flags |= CKF_SO_PIN_FINAL_TRY;
#ifndef WOLFPKCS11_NO_TIME
    if (cnt == WP11_MAX_LOGIN_FAILS_SO && now < expire)
        pInfo->flags |= CKF_SO_PIN_LOCKED;
#endif /* WOLFPKCS11_NO_TIME */

    cnt = WP11_Slot_TokenFailedLogin(slot, WP11_LOGIN_USER);
#ifndef WOLFPKCS11_NO_TIME
    expire = WP11_Slot_TokenFailedLoginExpire(slot, WP11_LOGIN_USER);
#endif

    if (cnt == WP11_MAX_LOGIN_FAILS_USER - 1)
        pInfo->flags |= CKF_USER_PIN_FINAL_TRY;
#ifndef WOLFPKCS11_NO_TIME
    if (cnt == WP11_MAX_LOGIN_FAILS_USER && now < expire)
        pInfo->flags |= CKF_USER_PIN_LOCKED;
#endif /* WOLFPKCS11_NO_TIME */

    if (WP11_Slot_IsTokenInitialized(slot))
        pInfo->flags |= CKF_TOKEN_INITIALIZED;

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
#ifndef WC_NO_RSA_OAEP
    CKM_RSA_PKCS_OAEP,
#endif
#ifdef WC_RSA_PSS
    CKM_RSA_PKCS_PSS,
#endif
#endif
#ifdef HAVE_ECC
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDH1_DERIVE,
#endif
#ifndef NO_DH
    CKM_DH_PKCS_KEY_PAIR_GEN,
    CKM_DH_PKCS_DERIVE,
#endif
#ifndef NO_AES
#ifdef HAVE_AES_CBC
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
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
#endif
#ifndef NO_HMAC
#ifndef NO_MD5
    CKM_MD5_HMAC,
#endif
#ifndef NO_SHA
    CKM_SHA1_HMAC,
#endif
#ifdef WOLFSSL_SHA224
    CKM_SHA224_HMAC,
#endif
#ifndef NO_SHA256
    CKM_SHA256_HMAC,
#endif
#ifdef WOLFSSL_SHA384
    CKM_SHA384_HMAC,
#endif
#ifdef WOLFSSL_SHA512
    CKM_SHA512_HMAC,
#endif
#endif
#ifdef WOLFSSL_HAVE_LMS
    CKM_HSS_KEY_PAIR_GEN,
    CKM_HSS,
#endif
};

/* Count of mechanisms in list. */
static int mechanismCnt = ((int)(sizeof(mechanismList)/sizeof(*mechanismList)));

/**
 * Get list of supported mechanism fo for the slot.
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
/* Info on ECDH mechanism. */
static CK_MECHANISM_INFO ecdhMechInfo = {
    256, 521, CKF_DERIVE
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
#ifndef NO_AES
#ifdef HAVE_AES_CBC
/* Info on AES-CBC mechanism. */
static CK_MECHANISM_INFO aesCbcMechInfo = {
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
#endif
#ifndef NO_HMAC
#ifndef NO_MD5
/* Info on HMAC-MD5 mechanism. */
static CK_MECHANISM_INFO hmacMd5MechInfo = {
    16, 512, CKF_SIGN | CKF_VERIFY
};
#endif
#ifndef NO_SHA
/* Info on HMAC-SHA1 mechanism. */
static CK_MECHANISM_INFO hmacSha1MechInfo = {
    20, 512, CKF_SIGN | CKF_VERIFY
};
#endif
#ifdef WOLFSSL_SHA224
/* Info on HMAC-SHA224 mechanism. */
static CK_MECHANISM_INFO hmacSha224MechInfo = {
    28, 512, CKF_SIGN | CKF_VERIFY
};
#endif
#ifndef NO_SHA256
/* Info on HMAC-SHA256 mechanism. */
static CK_MECHANISM_INFO hmacSha256MechInfo = {
    32, 512, CKF_SIGN | CKF_VERIFY
};
#endif
#ifdef WOLFSSL_SHA384
/* Info on HMAC-SHA384 mechanism. */
static CK_MECHANISM_INFO hmacSha384MechInfo = {
    48, 512, CKF_SIGN | CKF_VERIFY
};
#endif
#ifdef WOLFSSL_SHA512
/* Info on HMAC-SHA512 mechanism. */
static CK_MECHANISM_INFO hmacSha512MechInfo = {
    64, 512, CKF_SIGN | CKF_VERIFY
};
#endif
#endif
#ifdef WOLFSSL_HAVE_LMS
/* Info on HSS key generation mechanism. */
static CK_MECHANISM_INFO hssKgMechInfo = {
    5, 25, CKF_GENERATE_KEY_PAIR
};
/* Info on HSS mechanism. */
static CK_MECHANISM_INFO hssMechInfo = {
    5, 25, CKF_SIGN | CKF_VERIFY
};
#endif

/**
 * Get information on a mechanism.
 *
 * @param  slotID  [in]  Id of slot to use.
 * @param  type    [in]  Mechanism type.
 * @param  pInfo   [in]  Mechnism information copied into it.
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
    #ifdef WC_RSA_PSS
        case CKM_RSA_PKCS_PSS:
            XMEMCPY(pInfo, &rsaPssMechInfo, sizeof(CK_MECHANISM_INFO));
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
        case CKM_ECDH1_DERIVE:
            XMEMCPY(pInfo, &ecdhMechInfo, sizeof(CK_MECHANISM_INFO));
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
#ifdef HAVE_AES_CBC
        case CKM_AES_CBC_PAD:
        case CKM_AES_CBC:
            XMEMCPY(pInfo, &aesCbcMechInfo, sizeof(CK_MECHANISM_INFO));
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
#endif
#ifndef NO_HMAC
#ifndef NO_MD5
        case CKM_MD5_HMAC:
            XMEMCPY(pInfo, &hmacMd5MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef NO_SHA
        case CKM_SHA1_HMAC:
            XMEMCPY(pInfo, &hmacSha1MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_SHA224
        case CKM_SHA224_HMAC:
            XMEMCPY(pInfo, &hmacSha224MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifndef NO_SHA256
        case CKM_SHA256_HMAC:
            XMEMCPY(pInfo, &hmacSha256MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_SHA384
        case CKM_SHA384_HMAC:
            XMEMCPY(pInfo, &hmacSha384MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#ifdef WOLFSSL_SHA512
        case CKM_SHA512_HMAC:
            XMEMCPY(pInfo, &hmacSha512MechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
#endif
#ifdef WOLFSSL_HAVE_LMS
        case CKM_HSS_KEY_PAIR_GEN:
            XMEMCPY(pInfo, &hssKgMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
        case CKM_HSS:
            XMEMCPY(pInfo, &hssMechInfo, sizeof(CK_MECHANISM_INFO));
            break;
#endif
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

    if (ulPinLen < WP11_MIN_PIN_LEN || ulPinLen > WP11_MAX_PIN_LEN)
        return CKR_PIN_INCORRECT;

    if (WP11_Slot_IsTokenInitialized(slot)) {
        if (WP11_Slot_HasSession(slot))
            return CKR_SESSION_EXISTS;
        ret = WP11_Slot_CheckSOPin(slot, (char*)pPin, (int)ulPinLen);
        if (ret != 0)
            return CKR_PIN_INCORRECT;
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
    if (pPin == NULL)
        return CKR_ARGUMENTS_BAD;
    if (WP11_Session_GetState(session) != WP11_APP_STATE_RW_SO)
        return CKR_USER_NOT_LOGGED_IN;

    if (ulPinLen < WP11_MIN_PIN_LEN || ulPinLen > WP11_MAX_PIN_LEN)
        return CKR_PIN_INCORRECT;

    slot = WP11_Session_GetSlot(session);
    ret = WP11_Slot_SetUserPin(slot, (char*)pPin, (int)ulPinLen);
    if (ret != 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}
