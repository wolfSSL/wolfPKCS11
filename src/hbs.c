/* hbs.c
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
 */

/* LMS/HSS (RFC 8554) and XMSS/XMSS^MT (RFC 8391) hash-based signatures. */

#include "wp11_types.h"
#include "hbs.h"

#ifdef WOLFPKCS11_LMS
/* ===========================================================================
 * LMS/HSS (RFC 8554): verification and public-key import.
 *
 * Verify-only: this build imports raw HSS public keys and verifies
 * signatures. There is no private-key/keygen/sign or persisted signature
 * state here. The public key is self-describing, so wolfSSL derives the
 * parameter set from the key bytes on import; the CKA_HSS_LEVELS /
 * CKA_HSS_LMS_TYPE / CKA_HSS_LMOTS_TYPE attributes are optional and, when
 * supplied, are validated against the imported key.
 * ========================================================================= */

/* Map tree height -> RFC 8554 LMS typecode. Returns 0 on unknown height. */
static CK_LMS_TYPE wp11_HssHeightToLmsType(int h)
{
    switch (h) {
        case 5:  return CKL_LMS_SHA256_M32_H5;
        case 10: return CKL_LMS_SHA256_M32_H10;
        case 15: return CKL_LMS_SHA256_M32_H15;
        case 20: return CKL_LMS_SHA256_M32_H20;
        case 25: return CKL_LMS_SHA256_M32_H25;
        default: return 0;
    }
}

/* Map Winternitz -> LMOTS typecode. Returns 0 on unknown. */
static CK_LMOTS_TYPE wp11_HssWToLmotsType(int w)
{
    switch (w) {
        case 1: return CKL_LMOTS_SHA256_N32_W1;
        case 2: return CKL_LMOTS_SHA256_N32_W2;
        case 4: return CKL_LMOTS_SHA256_N32_W4;
        case 8: return CKL_LMOTS_SHA256_N32_W8;
        default: return 0;
    }
}

/* Import a raw HSS public key into the given wolfSSL LmsKey. wolfSSL derives
 * the parameter set from the key bytes (RFC 8554 self-describing public key),
 * so no parameters need to be set first. On failure the (partially
 * initialized) key is NOT freed here; the caller owns it. */
static int wp11_HssImportPub(LmsKey* key, int devId, const byte* pub,
    word32 pubLen)
{
    int ret;

    ret = wc_LmsKey_Init(key, NULL, devId);
    if (ret == 0)
        ret = wc_LmsKey_ImportPubRaw(key, pub, pubLen);
    return ret;
}

/* Validate caller-supplied HSS parameter attributes against the parameters
 * wolfSSL derived from the just-imported public key. Per the PKCS#11 v3.3 HSS
 * profile the public-key parameters are the individual CK_ULONG attributes
 * CKA_HSS_LEVELS, CKA_HSS_LMS_TYPE (top-level tree height encoding) and
 * CKA_HSS_LMOTS_TYPE (Winternitz encoding). Each is optional; a supplied value
 * that does not match the key is rejected with BAD_FUNC_ARG. levelsAttr,
 * lmsAttr and lmotsAttr are the raw attribute buffers (NULL when absent) with
 * lengths levelsLen/lmsLen/lmotsLen. */
static int wp11_HssCheckParamAttrs(LmsKey* key,
    const byte* levelsAttr, word32 levelsLen,
    const byte* lmsAttr, word32 lmsLen,
    const byte* lmotsAttr, word32 lmotsLen)
{
    int ret, levels = 0, height = 0, winternitz = 0;
    CK_ULONG v;

    ret = wc_LmsKey_GetParameters(key, &levels, &height, &winternitz);
    if (ret != 0)
        return ret;
    if (levelsAttr != NULL) {
        if (levelsLen != sizeof(v))
            return BAD_FUNC_ARG;
        XMEMCPY(&v, levelsAttr, sizeof(v));
        if (v != (CK_ULONG)levels)
            return BAD_FUNC_ARG;
    }
    if (lmsAttr != NULL) {
        if (lmsLen != sizeof(v))
            return BAD_FUNC_ARG;
        XMEMCPY(&v, lmsAttr, sizeof(v));
        if (v != (CK_ULONG)wp11_HssHeightToLmsType(height))
            return BAD_FUNC_ARG;
    }
    if (lmotsAttr != NULL) {
        if (lmotsLen != sizeof(v))
            return BAD_FUNC_ARG;
        XMEMCPY(&v, lmotsAttr, sizeof(v));
        if (v != (CK_ULONG)wp11_HssWToLmotsType(winternitz))
            return BAD_FUNC_ARG;
    }
    return 0;
}

#ifndef WOLFPKCS11_NO_STORE
/* Serialize the public key: keyData holds the raw RFC 8554 HSS public key. */
int wp11_Object_Encode_HssKey(WP11_Object* object)
{
    int ret;
    word32 pubLen = 0;
    unsigned char* oldData = object->keyData;
    int oldLen = object->keyDataLen;

    if (object->objClass != CKO_PUBLIC_KEY)
        return NOT_AVAILABLE_E;  /* verify-only: no private-key objects */

    ret = wc_LmsKey_GetPubLen(object->data.lmsKey, &pubLen);
    if (ret == 0) {
        object->keyData = (unsigned char*)XMALLOC(pubLen, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (object->keyData == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0) {
        ret = wc_LmsKey_ExportPubRaw(object->data.lmsKey, object->keyData,
            &pubLen);
        if (ret == 0)
            object->keyDataLen = (int)pubLen;
    }
    wp11_Object_EncodeDone(object, oldData, oldLen, pubLen, ret);
    return ret;
}

/* Reconstruct the live wolfSSL key from the serialized public key in keyData. */
int wp11_Object_Decode_HssKey(WP11_Object* object)
{
    int ret;

    if (object->objClass != CKO_PUBLIC_KEY)
        return NOT_AVAILABLE_E;

    /* Reload from the stored raw public key; wolfSSL re-derives the parameter
     * set from the key bytes (no separate parameters are persisted). */
    ret = wp11_HssImportPub(object->data.lmsKey, object->devId,
        object->keyData, (word32)object->keyDataLen);
    /* The object owns the live key on all paths (the import helper never frees
     * it), so encoded stays 0 for WP11_Object_Free to do the single free. */
    object->encoded = 0;
    return ret;
}

int wp11_Object_Load_HssKey(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

    ret = wp11_storage_open_readonly(WOLFPKCS11_STORE_HSSKEY_PUB, tokenId,
        objId, &storage);
    if (ret == 0) {
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        wp11_storage_close(storage);
    }
    return ret;
}

int wp11_Object_Store_HssKey(WP11_Object* object, int tokenId, int objId)
{
    int ret = 0;
    void* storage = NULL;

    if (object->keyData == NULL)
        ret = wp11_Object_Encode_HssKey(object);
    if (ret == 0)
        ret = wp11_storage_open(WOLFPKCS11_STORE_HSSKEY_PUB, tokenId, objId,
            object->keyDataLen, &storage);
    if (ret == 0) {
        ret = wp11_storage_write_array(storage, object->keyData,
            object->keyDataLen);
        ret = wp11_storage_close_write(storage, ret);
    }
    return ret;
}

#endif /* !WOLFPKCS11_NO_STORE */

/* Import an HSS public key from a C_CreateObject template. Following the
 * PKCS#11 v3.3 HSS profile the collected attributes are data[0]=CKA_HSS_LEVELS,
 * data[1]=CKA_HSS_LMS_TYPE, data[2]=CKA_HSS_LMOTS_TYPE (all optional CK_ULONG)
 * and data[3]=CKA_VALUE, the raw RFC 8554 public key. wolfSSL derives the
 * parameter set from the key bytes; any supplied CKA_HSS_* attribute is
 * validated against the derived parameters and a mismatch is rejected.
 * Private-key import is rejected: caller-supplied stateful private material is
 * a forgery vector and out of scope for verify-only support. */
int WP11_Object_SetHssKey(WP11_Object* object, unsigned char** data,
                          CK_ULONG* len)
{
    int ret = 0;
    LmsKey* newKey = NULL;

    if (object == NULL || data == NULL || len == NULL)
        return BAD_FUNC_ARG;
    if (object->objClass != CKO_PUBLIC_KEY)
        return BAD_FUNC_ARG;
    /* A public key must carry its value. There is no keygen path in a
     * verify-only build that would populate it later, so an absent
     * CKA_VALUE is an incomplete template rather than a deferred import;
     * reject it instead of creating an unusable object. */
    if (data[3] == NULL)
        return BAD_FUNC_ARG;

    if (object->lock != NULL)
        WP11_Lock_LockRW(object->lock);

    /* Import into a temporary key and swap it in only after it fully validates,
     * so a failed re-import (C_SetAttributeValue with a new CKA_VALUE) leaves
     * the existing key unchanged as PKCS#11 requires. */
    newKey = (LmsKey*)XMALLOC(sizeof(LmsKey), NULL, DYNAMIC_TYPE_KEY);
    if (newKey == NULL)
        ret = MEMORY_E;
    if (ret == 0) {
        XMEMSET(newKey, 0, sizeof(LmsKey));
        ret = wp11_HssImportPub(newKey, object->devId, data[3],
            (word32)len[3]);
    }
    if (ret == 0) {
        ret = wp11_HssCheckParamAttrs(newKey, data[0], (word32)len[0],
            data[1], (word32)len[1], data[2], (word32)len[2]);
    }
    if (ret == 0) {
        /* Replace the live key and drop the cached serialization so a later
         * store re-encodes from the new key instead of persisting stale bytes. */
        if (object->data.lmsKey != NULL) {
        #ifndef WOLFPKCS11_NO_STORE
            if (!object->encoded)
        #endif
                wc_LmsKey_Free(object->data.lmsKey);
            XFREE(object->data.lmsKey, NULL, DYNAMIC_TYPE_KEY);
        }
        object->data.lmsKey = newKey;
        newKey = NULL;
    #ifndef WOLFPKCS11_NO_STORE
        object->encoded = 0;
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = NULL;
        object->keyDataLen = 0;
    #endif
    }
    if (newKey != NULL) {
        wc_LmsKey_Free(newKey);
        XFREE(newKey, NULL, DYNAMIC_TYPE_KEY);
    }

    if (object->lock != NULL)
        WP11_Lock_UnlockRW(object->lock);
    return ret;
}

/**
 * Return the length of an HSS signature in bytes.
 *
 * @param  pub  [in]  HSS public key object.
 * @return  Length of HSS signature in bytes, 0 when it cannot be determined.
 */
word32 WP11_Hss_SigLen(WP11_Object* pub)
{
    word32 len = 0;

    if (pub->lock != NULL)
        WP11_Lock_LockRO(pub->lock);
    if (pub->data.lmsKey == NULL ||
            wc_LmsKey_GetSigLen(pub->data.lmsKey, &len) != 0) {
        len = 0;
    }
    if (pub->lock != NULL)
        WP11_Lock_UnlockRO(pub->lock);

    return len;
}

/* Verify an HSS signature over a raw message. Stateless on the verifier. */
int WP11_Hss_Verify(unsigned char* sig, word32 sigLen, unsigned char* data,
                    word32 dataLen, int* stat, WP11_Object* pub)
{
    int ret;
    word32 expSigLen = 0;

    if (pub == NULL || pub->data.lmsKey == NULL || stat == NULL)
        return BAD_FUNC_ARG;

    /* wc_LmsKey_Verify only reads the key and keeps its LmsState local, so
     * concurrent verifies on one object can share the RO lock. */
    if (pub->lock != NULL)
        WP11_Lock_LockRO(pub->lock);

    if (wc_LmsKey_GetSigLen(pub->data.lmsKey, &expSigLen) == 0 &&
            sigLen != expSigLen) {
        *stat = 0;
        ret = 0;
    }
    else {
        /* Unlike XMSS, whose wolfSSL verify rejects a zero-length message with
         * BAD_FUNC_ARG, wc_LmsKey_Verify accepts an empty message, so HSS needs
         * no dataLen == 0 special-case here (see WP11_Xmss_Verify). */
        ret = wc_LmsKey_Verify(pub->data.lmsKey, sig, sigLen, data,
            (int)dataLen);
        /* Only a genuine verification mismatch (SIG_VERIFY_E) maps to stat=0.
         * Remaining argument/state errors surface as a function failure so
         * they are not silently reported as an invalid signature. */
        if (ret == 0) {
            *stat = 1;
        }
        else if (ret == SIG_VERIFY_E) {
            *stat = 0;
            ret = 0;
        }
        else {
            *stat = 0;
        }
    }

    if (pub->lock != NULL)
        WP11_Lock_UnlockRO(pub->lock);

    return ret;
}

/* Serve HSS-specific attributes from a public-key object. */
int wp11_HssObject_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                           byte* data, CK_ULONG* len)
{
    int ret = 0;
    int levels = 0, height = 0, winternitz = 0;

    if (object == NULL || object->data.lmsKey == NULL || len == NULL)
        return BAD_FUNC_ARG;

    switch (type) {
        case CKA_HSS_LEVELS: {
            CK_ULONG v;
            ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels,
                &height, &winternitz);
            if (ret == 0) {
                v = (CK_ULONG)levels;
                if (data == NULL)
                    *len = sizeof(v);
                else if (*len < sizeof(v)) {
                    *len = sizeof(v);
                    ret = BUFFER_E;
                }
                else {
                    XMEMCPY(data, &v, sizeof(v));
                    *len = sizeof(v);
                }
            }
            break;
        }
        case CKA_HSS_LMS_TYPE: {
            CK_LMS_TYPE v;
            ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels,
                &height, &winternitz);
            if (ret == 0) {
                v = wp11_HssHeightToLmsType(height);
                if (v == 0)
                    ret = NOT_AVAILABLE_E;
                else if (data == NULL)
                    *len = sizeof(v);
                else if (*len < sizeof(v)) {
                    *len = sizeof(v);
                    ret = BUFFER_E;
                }
                else {
                    XMEMCPY(data, &v, sizeof(v));
                    *len = sizeof(v);
                }
            }
            break;
        }
        case CKA_HSS_LMOTS_TYPE: {
            CK_LMOTS_TYPE v;
            ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels,
                &height, &winternitz);
            if (ret == 0) {
                v = wp11_HssWToLmotsType(winternitz);
                if (v == 0)
                    ret = NOT_AVAILABLE_E;
                else if (data == NULL)
                    *len = sizeof(v);
                else if (*len < sizeof(v)) {
                    *len = sizeof(v);
                    ret = BUFFER_E;
                }
                else {
                    XMEMCPY(data, &v, sizeof(v));
                    *len = sizeof(v);
                }
            }
            break;
        }
        case CKA_HSS_LMS_TYPES:
        case CKA_HSS_LMOTS_TYPES: {
            /* wolfSSL uses uniform LMS/LMOTS parameters across all HSS levels, so
             * every array entry is the top-level type. Per-level types (allowed
             * by the PKCS#11 v3.3 profile) are not expressible by wolfSSL and are
             * not supported here. */
            CK_ULONG total;
            CK_ULONG fill;
            int i;
            ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels,
                &height, &winternitz);
            if (ret == 0) {
                total = (CK_ULONG)(sizeof(CK_ULONG) * levels);
                fill = (type == CKA_HSS_LMS_TYPES)
                    ? wp11_HssHeightToLmsType(height)
                    : wp11_HssWToLmotsType(winternitz);
                if (fill == 0)
                    ret = NOT_AVAILABLE_E;
                else if (data == NULL)
                    *len = total;
                else if (*len < total) {
                    *len = total;
                    ret = BUFFER_E;
                }
                else {
                    for (i = 0; i < levels; i++)
                        XMEMCPY(data + i * sizeof(CK_ULONG), &fill,
                            sizeof(CK_ULONG));
                    *len = total;
                }
            }
            break;
        }
        case CKA_HSS_KEYS_REMAINING:
            /* Remaining-signature count is a private-key/state property; not
             * available in a verify-only build. Return NOT_AVAILABLE_E like the
             * default arm; C_GetAttributeValue then sets ulValueLen. */
            ret = NOT_AVAILABLE_E;
            break;
        case CKA_VALUE:
            if (object->objClass == CKO_PUBLIC_KEY) {
                word32 pubLen = 0;
                ret = wc_LmsKey_GetPubLen(object->data.lmsKey, &pubLen);
                if (ret == 0) {
                    if (data == NULL)
                        *len = pubLen;
                    else if (*len < pubLen) {
                        *len = pubLen;
                        ret = BUFFER_E;
                    }
                    else {
                        ret = wc_LmsKey_ExportPubRaw(object->data.lmsKey,
                            data, &pubLen);
                        if (ret == 0)
                            *len = pubLen;
                    }
                }
            }
            else {
                *len = CK_UNAVAILABLE_INFORMATION;
                ret = NOT_AVAILABLE_E;
            }
            break;
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }
    return ret;
}

/* Check a supplied CKA_HSS_LMS_TYPES or CKA_HSS_LMOTS_TYPES array: one entry
 * per level, each equal to the key type. Caller holds the object lock. */
int wp11_HssCheckTypesAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                           const byte* data, CK_ULONG len)
{
    int ret;
    int levels = 0;
    int height = 0;
    int winternitz = 0;
    int i;
    CK_ULONG expected;
    CK_ULONG entry;

    if (object->data.lmsKey == NULL || data == NULL)
        return BAD_FUNC_ARG;

    ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels, &height,
        &winternitz);
    if (ret != 0)
        return ret;

    expected = (type == CKA_HSS_LMS_TYPES)
        ? (CK_ULONG)wp11_HssHeightToLmsType(height)
        : (CK_ULONG)wp11_HssWToLmotsType(winternitz);
    if (expected == 0)
        return BAD_FUNC_ARG;
    if (len != (CK_ULONG)(sizeof(CK_ULONG) * levels))
        return BAD_FUNC_ARG;

    for (i = 0; i < levels; i++) {
        XMEMCPY(&entry, data + i * sizeof(CK_ULONG), sizeof(entry));
        if (entry != expected)
            return BAD_FUNC_ARG;
    }

    return 0;
}
#endif /* WOLFPKCS11_LMS */

#ifdef WOLFPKCS11_XMSS
/* ===========================================================================
 * XMSS/XMSS^MT (RFC 8391): verification and public-key import.
 *
 * Verify-only. One wolfSSL XmssKey type serves both XMSS and XMSS^MT; the
 * PKCS#11 key type (CKK_XMSS vs CKK_XMSSMT) selects which via the is_xmssmt
 * flag. The raw public key carries the parameter-set OID in its leading
 * bytes, so wc_XmssKey_ImportPubRaw_ex derives the parameter set on import.
 * A CKA_PARAMETER_SET attribute is optional and, when supplied, is validated
 * against the OID in the key.
 * ========================================================================= */

/* Length of the parameter-set OID prefix in a raw RFC 8391 public key. wolfSSL
 * only exposes XMSS_OID_LEN when built with WOLFSSL_HAVE_XMSS and it is absent
 * from some released headers, so define our own to keep the build independent
 * of the wolfSSL version. */
#define WP11_XMSS_OID_LEN 4

/* Big-endian 32-bit read from a byte buffer (used to read the XMSS OID). */
static word32 wp11_HbsReadU32(const byte* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16)
         | ((word32)p[2] << 8)  |  (word32)p[3];
}

/* Import a raw XMSS/XMSS^MT public key into the given wolfSSL XmssKey, deriving
 * the parameter set from the embedded OID. is_xmssmt disambiguates the XMSS and
 * XMSS^MT OID namespaces (which overlap) and comes from the PKCS#11 key type.
 * When the caller supplies a CKA_PARAMETER_SET (params != NULL, the OID as a
 * CK_ULONG) it must match the OID in the public key. On failure the key is NOT
 * freed here; the caller owns it. */
static int wp11_XmssImportPub(XmssKey* key, int is_xmssmt, int devId,
    const byte* pub, word32 pubLen, const byte* params, word32 paramsLen)
{
    int ret;

    ret = wc_XmssKey_Init(key, NULL, devId);
    if (ret == 0 && params != NULL) {
        CK_ULONG userOid;
        if (paramsLen != sizeof(CK_ULONG) || pubLen < WP11_XMSS_OID_LEN) {
            ret = BAD_FUNC_ARG;
        }
        else {
            XMEMCPY(&userOid, params, sizeof(userOid));
            if (userOid != (CK_ULONG)wp11_HbsReadU32(pub))
                ret = BAD_FUNC_ARG;
        }
    }
    if (ret == 0)
        ret = wc_XmssKey_ImportPubRaw_ex(key, pub, pubLen, is_xmssmt);
    return ret;
}

#ifndef WOLFPKCS11_NO_STORE
/* Serialize the public key: keyData holds the raw RFC 8391 public key. */
int wp11_Object_Encode_XmssKey(WP11_Object* object)
{
    int ret;
    word32 pubLen = 0;
    unsigned char* oldData = object->keyData;
    int oldLen = object->keyDataLen;

    if (object->objClass != CKO_PUBLIC_KEY)
        return NOT_AVAILABLE_E;

    ret = wc_XmssKey_GetPubLen(object->data.xmssKey, &pubLen);
    if (ret == 0) {
        object->keyData = (unsigned char*)XMALLOC(pubLen, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (object->keyData == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0) {
        ret = wc_XmssKey_ExportPubRaw(object->data.xmssKey, object->keyData,
            &pubLen);
        if (ret == 0)
            object->keyDataLen = (int)pubLen;
    }
    wp11_Object_EncodeDone(object, oldData, oldLen, pubLen, ret);
    return ret;
}

int wp11_Object_Decode_XmssKey(WP11_Object* object)
{
    int ret;

    if (object->objClass != CKO_PUBLIC_KEY)
        return NOT_AVAILABLE_E;

    /* Reload from the stored raw public key; wolfSSL re-derives the parameter
     * set from the embedded OID (no separate parameter set is persisted). */
    ret = wp11_XmssImportPub(object->data.xmssKey,
        (object->type == CKK_XMSSMT) ? 1 : 0, object->devId, object->keyData,
        (word32)object->keyDataLen, NULL, 0);
    /* Object owns the key on all paths; encoded stays 0 for the single free in
     * WP11_Object_Free. See wp11_Object_Decode_HssKey. */
    object->encoded = 0;
    return ret;
}

int wp11_Object_Load_XmssKey(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

    ret = wp11_storage_open_readonly(WOLFPKCS11_STORE_XMSSKEY_PUB, tokenId,
        objId, &storage);
    if (ret == 0) {
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        wp11_storage_close(storage);
    }
    return ret;
}

int wp11_Object_Store_XmssKey(WP11_Object* object, int tokenId,
    int objId)
{
    int ret = 0;
    void* storage = NULL;

    if (object->keyData == NULL)
        ret = wp11_Object_Encode_XmssKey(object);
    if (ret == 0)
        ret = wp11_storage_open(WOLFPKCS11_STORE_XMSSKEY_PUB, tokenId, objId,
            object->keyDataLen, &storage);
    if (ret == 0) {
        ret = wp11_storage_write_array(storage, object->keyData,
            object->keyDataLen);
        ret = wp11_storage_close_write(storage, ret);
    }
    return ret;
}

#endif /* !WOLFPKCS11_NO_STORE */

/* Import an XMSS/XMSS^MT public key from a C_CreateObject template. data[1] is
 * the raw RFC 8391 public key; data[0] (CKA_PARAMETER_SET, the OID as a
 * CK_ULONG) is optional and, when present, is validated against the key.
 * Private-key import is rejected. */
int WP11_Object_SetXmssKey(WP11_Object* object, unsigned char** data,
                           CK_ULONG* len)
{
    int ret = 0;
    XmssKey* newKey = NULL;

    if (object == NULL || data == NULL || len == NULL)
        return BAD_FUNC_ARG;
    if (object->objClass != CKO_PUBLIC_KEY)
        return BAD_FUNC_ARG;
    /* A public key must carry its value; an absent CKA_VALUE is an
     * incomplete template (no keygen path fills it later). Reject it. */
    if (data[1] == NULL)
        return BAD_FUNC_ARG;

    if (object->lock != NULL)
        WP11_Lock_LockRW(object->lock);

    /* Import into a temporary key and swap it in only after it validates, so a
     * failed re-import leaves the existing key unchanged (PKCS#11 requires a
     * failed C_SetAttributeValue to be a no-op). */
    newKey = (XmssKey*)XMALLOC(sizeof(XmssKey), NULL, DYNAMIC_TYPE_KEY);
    if (newKey == NULL)
        ret = MEMORY_E;
    if (ret == 0) {
        XMEMSET(newKey, 0, sizeof(XmssKey));
        ret = wp11_XmssImportPub(newKey, (object->type == CKK_XMSSMT) ? 1 : 0,
            object->devId, data[1], (word32)len[1], data[0], (word32)len[0]);
    }
    if (ret == 0) {
        /* Replace the live key and drop the cached serialization so a later
         * store re-encodes from the new key. */
        if (object->data.xmssKey != NULL) {
        #ifndef WOLFPKCS11_NO_STORE
            if (!object->encoded)
        #endif
                wc_XmssKey_Free(object->data.xmssKey);
            XFREE(object->data.xmssKey, NULL, DYNAMIC_TYPE_KEY);
        }
        object->data.xmssKey = newKey;
        newKey = NULL;
    #ifndef WOLFPKCS11_NO_STORE
        object->encoded = 0;
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = NULL;
        object->keyDataLen = 0;
    #endif
    }
    if (newKey != NULL) {
        wc_XmssKey_Free(newKey);
        XFREE(newKey, NULL, DYNAMIC_TYPE_KEY);
    }

    if (object->lock != NULL)
        WP11_Lock_UnlockRW(object->lock);
    return ret;
}

/**
 * Return the length of an XMSS/XMSS^MT signature in bytes.
 *
 * @param  pub  [in]  XMSS public key object.
 * @return  Length of XMSS signature in bytes, 0 when it cannot be determined.
 */
word32 WP11_Xmss_SigLen(WP11_Object* pub)
{
    word32 len = 0;

    if (pub->lock != NULL)
        WP11_Lock_LockRO(pub->lock);
    if (pub->data.xmssKey == NULL ||
            wc_XmssKey_GetSigLen(pub->data.xmssKey, &len) != 0) {
        len = 0;
    }
    if (pub->lock != NULL)
        WP11_Lock_UnlockRO(pub->lock);

    return len;
}

/* Verify an XMSS/XMSS^MT signature over a raw message. Stateless. */
int WP11_Xmss_Verify(unsigned char* sig, word32 sigLen, unsigned char* data,
                     word32 dataLen, int* stat, WP11_Object* pub)
{
    int ret;
    word32 expSigLen = 0;

    if (pub == NULL || pub->data.xmssKey == NULL || stat == NULL)
        return BAD_FUNC_ARG;

    /* wc_XmssKey_Verify only reads the key and keeps its XmssState local, so
     * concurrent verifies on one object can share the RO lock. */
    if (pub->lock != NULL)
        WP11_Lock_LockRO(pub->lock);

    if (wc_XmssKey_GetSigLen(pub->data.xmssKey, &expSigLen) == 0 &&
            sigLen != expSigLen) {
        *stat = 0;
        ret = 0;
    }
    /* wolfSSL's XMSS verify rejects an empty message with BAD_FUNC_ARG. */
    else if (dataLen == 0) {
        *stat = 0;
        ret = 0;
    }
    else {
        ret = wc_XmssKey_Verify(pub->data.xmssKey, sig, sigLen, data,
            (int)dataLen);
        /* Only SIG_VERIFY_E maps to stat=0; other argument/state errors
         * surface as a function failure so they are not silently reported as
         * an invalid signature. */
        if (ret == 0) {
            *stat = 1;
        }
        else if (ret == SIG_VERIFY_E) {
            *stat = 0;
            ret = 0;
        }
        else {
            *stat = 0;
        }
    }

    if (pub->lock != NULL)
        WP11_Lock_UnlockRO(pub->lock);

    return ret;
}

/* Serve XMSS-specific attributes from a public-key object. */
int wp11_XmssObject_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                            byte* data, CK_ULONG* len)
{
    int ret = 0;

    if (object == NULL || object->data.xmssKey == NULL || len == NULL)
        return BAD_FUNC_ARG;

    switch (type) {
        case CKA_VALUE:
            if (object->objClass == CKO_PUBLIC_KEY) {
                word32 pubLen = 0;
                ret = wc_XmssKey_GetPubLen(object->data.xmssKey, &pubLen);
                if (ret == 0) {
                    if (data == NULL)
                        *len = pubLen;
                    else if (*len < pubLen) {
                        *len = pubLen;
                        ret = BUFFER_E;
                    }
                    else {
                        ret = wc_XmssKey_ExportPubRaw(object->data.xmssKey,
                            data, &pubLen);
                        if (ret == 0)
                            *len = pubLen;
                    }
                }
            }
            else {
                *len = CK_UNAVAILABLE_INFORMATION;
                ret = NOT_AVAILABLE_E;
            }
            break;
        case CKA_PARAMETER_SET: {
            /* The XMSS parameter set is identified by the OID in the leading
             * bytes of the raw public key; return it as a CK_ULONG. */
            CK_ULONG v;
            word32 pubLen = 0;
            byte* raw;

            if (object->objClass != CKO_PUBLIC_KEY) {
                *len = CK_UNAVAILABLE_INFORMATION;
                ret = NOT_AVAILABLE_E;
                break;
            }
            if (data == NULL) {
                *len = sizeof(v);
                break;
            }
            if (*len < sizeof(v)) {
                *len = sizeof(v);
                ret = BUFFER_E;
                break;
            }
            ret = wc_XmssKey_GetPubLen(object->data.xmssKey, &pubLen);
            if (ret == 0 && pubLen < WP11_XMSS_OID_LEN)
                ret = NOT_AVAILABLE_E;
            if (ret == 0) {
                raw = (byte*)XMALLOC(pubLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (raw == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    ret = wc_XmssKey_ExportPubRaw(object->data.xmssKey, raw,
                        &pubLen);
                    if (ret == 0) {
                        v = (CK_ULONG)wp11_HbsReadU32(raw);
                        XMEMCPY(data, &v, sizeof(v));
                        *len = sizeof(v);
                    }
                    XFREE(raw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                }
            }
            break;
        }
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }
    return ret;
}
#endif /* WOLFPKCS11_XMSS */

