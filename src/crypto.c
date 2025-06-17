/* crypto.c
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

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#else
#include "user_settings.h"
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <wolfpkcs11/pkcs11.h>
#include <wolfpkcs11/internal.h>

#define ATTR_TYPE_ULONG        0
#define ATTR_TYPE_BOOL         1
#define ATTR_TYPE_DATA         2
#define ATTR_TYPE_DATE         3

#define PRF_KEY_SIZE            48

#define CHECK_KEYTYPE(kt) \
   (kt == CKK_RSA || kt == CKK_EC || kt == CKK_DH || \
    kt == CKK_AES || kt == CKK_HKDF || kt == CKK_GENERIC_SECRET) ? \
    CKR_OK : CKR_ATTRIBUTE_VALUE_INVALID

#define CHECK_KEYCLASS(kc) \
    (kc == CKO_PRIVATE_KEY || kc == CKO_PUBLIC_KEY || kc == CKO_SECRET_KEY)? CKR_OK : CKR_ATTRIBUTE_VALUE_INVALID

#define CHECK_WRAPPABLE(kc, kt) \
    ( \
            (kc == CKO_PRIVATE_KEY && kt == CKK_RSA) || \
            (kc == CKO_SECRET_KEY && kt == CKK_AES) || \
            (kc == CKO_SECRET_KEY && kt == CKK_GENERIC_SECRET) \
    ) \
    ? CKR_OK: CKR_KEY_NOT_WRAPPABLE

#ifndef NO_RSA
/* RSA key data attributes. */
static CK_ATTRIBUTE_TYPE rsaKeyParams[] = {
    CKA_MODULUS,
    CKA_PRIVATE_EXPONENT,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_COEFFICIENT,
    CKA_PUBLIC_EXPONENT,
    CKA_MODULUS_BITS,
};
/* Count of RSA key data attributes. */
#define RSA_KEY_PARAMS_CNT    (sizeof(rsaKeyParams)/sizeof(*rsaKeyParams))
#endif

#ifdef HAVE_ECC
/* EC key data attributes. */
static CK_ATTRIBUTE_TYPE ecKeyParams[] = {
    CKA_EC_PARAMS,
    CKA_VALUE,
    CKA_EC_POINT
};
/* Count of EC key data attributes. */
#define EC_KEY_PARAMS_CNT     (sizeof(ecKeyParams)/sizeof(*ecKeyParams))
#endif

#ifndef NO_DH
/* DH key data attributes. */
static CK_ATTRIBUTE_TYPE dhKeyParams[] = {
    CKA_PRIME,
    CKA_BASE,
    CKA_VALUE,
};
/* Count of DH key data attributes. */
#define DH_KEY_PARAMS_CNT     (sizeof(dhKeyParams)/sizeof(*dhKeyParams))
#endif

/* Secret key data attributes. */
static CK_ATTRIBUTE_TYPE secretKeyParams[] = {
    CKA_VALUE_LEN,
    CKA_VALUE,
};
/* Count of secret key data attributes. */
#define SECRET_KEY_PARAMS_CNT (sizeof(secretKeyParams)/sizeof(*secretKeyParams))

/* Certificate data attributes */
static CK_ATTRIBUTE_TYPE certParams[] = {
    CKA_CERTIFICATE_TYPE,
    CKA_VALUE,
};
#define CERT_PARAMS_CNT     (sizeof(certParams)/sizeof(*certParams))

#ifdef WOLFPKCS11_NSS
static CK_ATTRIBUTE_TYPE trustParams[] = {
    CKA_CERT_SHA1_HASH,
    CKA_CERT_MD5_HASH,
    CKA_TRUST_SERVER_AUTH,
    CKA_TRUST_CLIENT_AUTH,
    CKA_TRUST_EMAIL_PROTECTION,
    CKA_TRUST_CODE_SIGNING,
    CKA_TRUST_STEP_UP_APPROVED,
};
#define TRUST_PARAMS_CNT    (sizeof(trustParams)/sizeof(*trustParams))
#endif

/* Identify maximum count for stack array. */
#ifndef NO_RSA
#define OBJ_MAX_PARAMS        RSA_KEY_PARAMS_CNT
#elif defined(HAVE_ECC)
#define OBJ_MAX_PARAMS        EC_KEY_PARAMS_CNT
#elif !defined(NO_DH)
#define OBJ_MAX_PARAMS        DH_KEY_PARAMS_CNT
#else
#define OBJ_MAX_PARAMS        SECRET_KEY_PARAMS_CNT
#endif

typedef struct AttributeType {
    CK_ATTRIBUTE_TYPE attr;            /* Crypto-Ki attribute                 */
    byte type;                         /* Data type associated with attribute */
} AttributeType;

/* List of recognized attributes and their data type. */
static AttributeType attrType[] = {
    { CKA_CLASS,                       ATTR_TYPE_ULONG },
    { CKA_TOKEN,                       ATTR_TYPE_DATA  },
    { CKA_PRIVATE,                     ATTR_TYPE_BOOL  },
    { CKA_LABEL,                       ATTR_TYPE_DATA  },
    { CKA_APPLICATION,                 ATTR_TYPE_DATA  },
    { CKA_VALUE,                       ATTR_TYPE_DATA  },
    { CKA_OBJECT_ID,                   ATTR_TYPE_DATA  },
    { CKA_OWNER,                       ATTR_TYPE_DATA  },
    { CKA_TRUSTED,                     ATTR_TYPE_BOOL  },
    { CKA_KEY_TYPE,                    ATTR_TYPE_ULONG },
    { CKA_SUBJECT,                     ATTR_TYPE_DATA  },
    { CKA_ID,                          ATTR_TYPE_DATA  },
    { CKA_SENSITIVE,                   ATTR_TYPE_BOOL  },
    { CKA_ENCRYPT,                     ATTR_TYPE_BOOL  },
    { CKA_DECRYPT,                     ATTR_TYPE_BOOL  },
    { CKA_WRAP,                        ATTR_TYPE_BOOL  },
    { CKA_UNWRAP,                      ATTR_TYPE_BOOL  },
    { CKA_SIGN,                        ATTR_TYPE_BOOL  },
    { CKA_SIGN_RECOVER,                ATTR_TYPE_BOOL  },
    { CKA_VERIFY,                      ATTR_TYPE_BOOL  },
    { CKA_VERIFY_RECOVER,              ATTR_TYPE_BOOL  },
    { CKA_DERIVE,                      ATTR_TYPE_BOOL  },
    { CKA_START_DATE,                  ATTR_TYPE_DATE  },
    { CKA_END_DATE,                    ATTR_TYPE_DATE  },
    { CKA_MODULUS,                     ATTR_TYPE_DATA  },
    { CKA_MODULUS_BITS,                ATTR_TYPE_ULONG },
    { CKA_PUBLIC_EXPONENT,             ATTR_TYPE_DATA  },
    { CKA_PRIVATE_EXPONENT,            ATTR_TYPE_DATA  },
    { CKA_PRIME_1,                     ATTR_TYPE_DATA  },
    { CKA_PRIME_2,                     ATTR_TYPE_DATA  },
    { CKA_EXPONENT_1,                  ATTR_TYPE_DATA  },
    { CKA_EXPONENT_2,                  ATTR_TYPE_DATA  },
    { CKA_COEFFICIENT,                 ATTR_TYPE_DATA  },
    { CKA_PUBLIC_KEY_INFO,             ATTR_TYPE_DATA  },
    { CKA_PRIME,                       ATTR_TYPE_DATA  },
    { CKA_BASE,                        ATTR_TYPE_DATA  },
    { CKA_PRIME_BITS,                  ATTR_TYPE_ULONG },
    { CKA_VALUE_BITS,                  ATTR_TYPE_ULONG },
    { CKA_VALUE_LEN,                   ATTR_TYPE_ULONG },
    { CKA_EXTRACTABLE,                 ATTR_TYPE_BOOL  },
    { CKA_LOCAL,                       ATTR_TYPE_BOOL  },
    { CKA_NEVER_EXTRACTABLE,           ATTR_TYPE_BOOL  },
    { CKA_ALWAYS_SENSITIVE,            ATTR_TYPE_BOOL  },
    { CKA_KEY_GEN_MECHANISM,           ATTR_TYPE_ULONG },
    { CKA_MODIFIABLE,                  ATTR_TYPE_BOOL  },
    { CKA_COPYABLE,                    ATTR_TYPE_BOOL  },
    { CKA_DESTROYABLE,                 ATTR_TYPE_BOOL  },
    { CKA_EC_PARAMS,                   ATTR_TYPE_DATA  },
    { CKA_EC_POINT,                    ATTR_TYPE_DATA  },
    { CKA_ALWAYS_AUTHENTICATE,         ATTR_TYPE_BOOL  },
    { CKA_WRAP_WITH_TRUSTED,           ATTR_TYPE_BOOL  },
    { CKA_HW_FEATURE_TYPE,             ATTR_TYPE_ULONG },
    { CKA_RESET_ON_INIT,               ATTR_TYPE_BOOL  },
    { CKA_HAS_RESET,                   ATTR_TYPE_BOOL  },
    { CKA_WRAP_TEMPLATE,               ATTR_TYPE_DATA  },
    { CKA_UNWRAP_TEMPLATE,             ATTR_TYPE_DATA  },
    { CKA_DERIVE_TEMPLATE,             ATTR_TYPE_DATA  },
    { CKA_ALLOWED_MECHANISMS,          ATTR_TYPE_DATA  },
    { CKA_CERTIFICATE_TYPE,            ATTR_TYPE_ULONG },
    { CKA_CERTIFICATE_CATEGORY,        ATTR_TYPE_ULONG },
    { CKA_ID,                          ATTR_TYPE_DATA  },
    { CKA_ISSUER,                      ATTR_TYPE_DATA  },
    { CKA_SERIAL_NUMBER,               ATTR_TYPE_DATA  },
    { CKA_PUBLIC_KEY_INFO,             ATTR_TYPE_DATA  },
    { CKA_URL,                         ATTR_TYPE_DATA  },
    { CKA_HASH_OF_SUBJECT_PUBLIC_KEY,  ATTR_TYPE_DATA  },
    { CKA_HASH_OF_ISSUER_PUBLIC_KEY,   ATTR_TYPE_DATA  },
    { CKA_NAME_HASH_ALGORITHM,         ATTR_TYPE_ULONG },
    { CKA_CHECK_VALUE,                 ATTR_TYPE_DATA  },
#ifdef WOLFPKCS11_NSS
    { CKA_CERT_SHA1_HASH,              ATTR_TYPE_DATA  },
    { CKA_CERT_MD5_HASH,               ATTR_TYPE_DATA  },
    { CKA_TRUST_SERVER_AUTH,           ATTR_TYPE_ULONG },
    { CKA_TRUST_CLIENT_AUTH,           ATTR_TYPE_ULONG },
    { CKA_TRUST_EMAIL_PROTECTION,      ATTR_TYPE_ULONG },
    { CKA_TRUST_CODE_SIGNING,          ATTR_TYPE_ULONG },
    { CKA_TRUST_STEP_UP_APPROVED,      ATTR_TYPE_BOOL  },
#endif
};
/* Count of elements in attribute type list. */
#define ATTR_TYPE_SIZE     (sizeof(attrType) / sizeof(*attrType))

/**
 * Find the attribute type in the template.
 *
 * @param  pTemplate  [in]   Template of attributed for an object.
 * @param  ulCount    [in]   Number of attribute triplets in template.
 * @param  type       [in]   Attribute type to find.
 * @param  attribute  [out]  Attribute with the type.
 *                           NULL when type not found.
 */
static void FindAttributeType(CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount,
                              CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE** attribute)
{
    int i;

    *attribute = NULL;
    for (i = 0; i < (int)ulCount; i++) {
        if (pTemplate[i].type == type) {
            *attribute = &pTemplate[i];
            break;
        }
    }
}

static CK_RV FindValidAttributeType(CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount,
                        CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE** attr, size_t sz)
{
    FindAttributeType(pTemplate, ulCount, type, attr);
    if (*attr == NULL) {
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if ((*attr)->pValue == NULL || (*attr)->ulValueLen != sz) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

/**
 * Check the value and length are valid for the data type of the attributes in
 * the template.
 * Boolean value is checked for CK_TRUE or CK_FALSE when setting attributes.
 *
 * @param  pTemplate  [in]  Template of attributes for object.
 * @param  ulCount    [in]  Number of attribute triplets in template.
 * @param  set        [in]  Whether attributes are being used to set or get
 *                          value.
 * @return  CKR_ATTRIBUTE_TYPE_INVALID if the attribute type is not supported.
 *          CKR_ATTRIBUTE_VALUE_INVALID if value is not valid for data type.
 *          CKR_BUFFER_TOO_SMALL if length is too short for data type.
 *          CKR_OK on success.
 */
static CK_RV CheckAttributes(CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount, int set)
{
    CK_ATTRIBUTE* attr;
    int i, j;

    for (i = 0; i < (int)ulCount; i++) {
        attr = &pTemplate[i];
        for (j = 0; j < (int)ATTR_TYPE_SIZE; j++) {
            if (attrType[j].attr == attr->type) {
                break;
            }
        }
        if (j == ATTR_TYPE_SIZE)
            return CKR_ATTRIBUTE_TYPE_INVALID;

        if (attrType[j].type == ATTR_TYPE_ULONG) {
            if (attr->pValue == NULL && set)
                return CKR_ATTRIBUTE_VALUE_INVALID;
            if ((attr->pValue != NULL) &&
                (attr->ulValueLen != sizeof(CK_ULONG)))
                return CKR_BUFFER_TOO_SMALL;
        }
        else if (attrType[j].type == ATTR_TYPE_BOOL) {
            if (attr->pValue == NULL && set)
                return CKR_ATTRIBUTE_VALUE_INVALID;
            if ((attr->pValue != NULL) &&
                (attr->ulValueLen != sizeof(CK_BBOOL)))
                return CKR_BUFFER_TOO_SMALL;
            if (set && *(CK_BBOOL*)attr->pValue != CK_TRUE &&
                                         *(CK_BBOOL*)attr->pValue != CK_FALSE) {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
        }
        else if (attrType[j].type == ATTR_TYPE_DATE) {
            if (attr->pValue == NULL && set)
                return CKR_ATTRIBUTE_VALUE_INVALID;
            if ((attr->pValue != NULL) &&
                (attr->ulValueLen != sizeof(CK_DATE)))
                return CKR_BUFFER_TOO_SMALL;
        }
        else if (attrType[j].type == ATTR_TYPE_DATA) {
            if (set && attr->ulValueLen == CK_UNAVAILABLE_INFORMATION)
                return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    return CKR_OK;
}

static CK_RV SetInitialStates(WP11_Object* key)
{
    CK_RV rv;
    CK_BBOOL trueVar = CK_TRUE;
    CK_BBOOL getVar;
    CK_ULONG getVarLen = sizeof(CK_BBOOL);

    rv = WP11_Object_GetAttr(key, CKA_SENSITIVE, &getVar, &getVarLen);
    if ((rv == CKR_OK) && (getVar == CK_TRUE)) {
        rv = WP11_Object_SetAttr(key, CKA_ALWAYS_SENSITIVE, &trueVar,
                                    sizeof(CK_BBOOL));
    }
    if (rv == CKR_OK) {
        rv = WP11_Object_GetAttr(key, CKA_EXTRACTABLE, &getVar, &getVarLen);
        if ((rv == CKR_OK) && (getVar == CK_FALSE)) {
            rv = WP11_Object_SetAttr(key, CKA_NEVER_EXTRACTABLE, &trueVar,
                                    sizeof(CK_BBOOL));
        }
    }
    return rv;
}

static CK_RV TemplateHasAttribute(CK_ATTRIBUTE_TYPE type,
        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    for (CK_ULONG i = 0; i < ulCount; i++) {
        if (type == pTemplate[i].type)
            return CKR_OK;
    }

    return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV SetIfNotFound(WP11_Object* obj, CK_ATTRIBUTE_TYPE type,
                           CK_BBOOL state, CK_ATTRIBUTE_PTR pTemplate,
                           CK_ULONG ulCount)
{
    CK_RV ret;

    /* False states are always default */
    if (state == CK_FALSE) {
        return CKR_OK;
    }

    if (TemplateHasAttribute(type, pTemplate, ulCount) == CKR_OK) {
        return CKR_OK;
    }

    ret = WP11_Object_SetAttr(obj, type, &state, sizeof(CK_BBOOL));
    return ret;
}

static CK_RV SetAttributeDefaults(WP11_Object* obj, CK_OBJECT_CLASS keyType,
                                  CK_ATTRIBUTE_PTR pTemplate,
                                  CK_ULONG ulCount)
{
    CK_RV ret = CKR_OK;
    CK_BBOOL trueVal = CK_TRUE;
    CK_BBOOL falseVal = CK_FALSE;
    CK_BBOOL encrypt = CK_TRUE;
    CK_BBOOL recover = CK_TRUE;
    CK_BBOOL wrap = CK_TRUE;
    CK_BBOOL derive = (keyType == CKO_PUBLIC_KEY ? CK_FALSE : CK_TRUE);
    CK_BBOOL verify = CK_TRUE;
    CK_BBOOL sign = CK_FALSE;

    CK_KEY_TYPE type = WP11_Object_GetType(obj);

    switch (type) {
        /* If we implement DSA
        case CKK_DSA:
            encrypt = CK_FALSE;
            recover = CK_FALSE;
            wrap = CK_FALSE;
            sign = CK_TRUE;
            derive = CK_FALSE;
            break;
        */
        case CKK_DH:
            verify = CK_FALSE;
            derive = CK_TRUE;
            encrypt = CK_FALSE;
            recover = CK_FALSE;
            wrap = CK_FALSE;
            break;
        case CKK_EC:
            derive = CK_FALSE;
            verify = CK_FALSE;
            encrypt = CK_FALSE;
            recover = CK_FALSE;
            wrap = CK_FALSE;
            sign = CK_TRUE;
            break;
    }

    /* Defaults if not set */
    switch (keyType) {
        case CKO_PUBLIC_KEY:
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_ENCRYPT, encrypt, pTemplate,
                                    ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_VERIFY, verify, pTemplate,
                                    ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_VERIFY_RECOVER, recover, pTemplate,
                                    ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_WRAP, wrap, pTemplate, ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_DERIVE, derive, pTemplate,
                                    ulCount);
            break;
        case CKO_SECRET_KEY:
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_EXTRACTABLE, trueVal, pTemplate,
                                    ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_ENCRYPT, trueVal, pTemplate,
                                    ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_DECRYPT, trueVal, pTemplate,
                                    ulCount);
            /* CKA_SIGN / CKA_VERIFY default false */
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_WRAP, trueVal, pTemplate, ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_UNWRAP, trueVal, pTemplate,
                                    ulCount);
            break;
        case CKO_PRIVATE_KEY:
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_EXTRACTABLE, trueVal, pTemplate,
                                    ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_DECRYPT, encrypt, pTemplate,
                                    ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_SIGN, sign, pTemplate, ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_SIGN_RECOVER, recover, pTemplate,
                                    ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_UNWRAP, wrap, pTemplate, ulCount);
            if (ret == CKR_OK)
                ret = SetIfNotFound(obj, CKA_DERIVE, derive, pTemplate,
                                    ulCount);
            break;
    }

    /* Next two are forced attributes */
    if (ret == CKR_OK &&
        (keyType == CKO_PRIVATE_KEY || keyType == CKO_SECRET_KEY)) {
            ret = WP11_Object_SetAttr(obj, CKA_ALWAYS_SENSITIVE, &falseVal,
                                      sizeof(CK_BBOOL));
            if (ret == CKR_OK)
                ret = WP11_Object_SetAttr(obj, CKA_NEVER_EXTRACTABLE, &falseVal,
                                          sizeof(CK_BBOOL));
    }

    return ret;
}

/**
 * Set the values of the attributes into the object.
 *
 * @param  session    [in]  Session object.
 * @param  obj        [in]  Object to set value against.
 * @param  pTemplate  [in]  Template of attributes set against object.
 * @param  ulCount    [in]  Number of attribute triplets in template.
 * @return  CKR_ARGUMENTS_BAD when pTemplate is NULL.
 *          CKR_SESSION_READ_ONLY when the session cannot modify objects.
 *          CKR_ATTRIBUTE_TYPE_INVALID if the attribute type is not supported.
 *          CKR_ATTRIBUTE_VALUE_INVALID if value is not valid for data type.
 *          CKR_BUFFER_TOO_SMALL if an attribute length is too short.
 *          CK_UNAVAILABLE_INFORMATION when an attribute type is not supported
 *          for modification.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when getting a value fails.
 *          CKR_OK on success.
 */
static CK_RV SetAttributeValue(WP11_Session* session, WP11_Object* obj,
                               CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                               CK_BBOOL newObject)
{
    int ret = 0;
    CK_RV rv;
    CK_ATTRIBUTE* attr;
    int i, j;
    unsigned char* data[OBJ_MAX_PARAMS] = { 0, };
    CK_ULONG len[OBJ_MAX_PARAMS] = { 0, };
    CK_ATTRIBUTE_TYPE* attrs = NULL;
    int cnt;
    CK_BBOOL attrsFound = 0;
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS objClass;
    CK_BBOOL getVar;
    CK_ULONG getVarLen = 1;

    if (pTemplate == NULL)
        return CKR_ARGUMENTS_BAD;
    if (!WP11_Session_IsRW(session))
        return CKR_SESSION_READ_ONLY;

    rv = CheckAttributes(pTemplate, ulCount, 1);
    if (rv != CKR_OK)
        return rv;


    type = WP11_Object_GetType(obj);
    objClass = WP11_Object_GetClass(obj);
    if (objClass == CKO_CERTIFICATE) {
        attrs = certParams;
        cnt = CERT_PARAMS_CNT;
    }
#ifdef WOLFPKCS11_NSS
    else if (objClass == CKO_NSS_TRUST) {
        attrs = trustParams;
        cnt = TRUST_PARAMS_CNT;
    }
#endif
    else {
        /* Get the value and length of key specific attribute types. */
        switch (type) {
        #ifndef NO_RSA
            case CKK_RSA:
                attrs = rsaKeyParams;
                cnt = RSA_KEY_PARAMS_CNT;
                break;
        #endif
        #ifdef HAVE_ECC
            case CKK_EC:
                attrs = ecKeyParams;
                cnt = EC_KEY_PARAMS_CNT;
                break;
        #endif
        #ifndef NO_DH
            case CKK_DH:
                attrs = dhKeyParams;
                cnt = DH_KEY_PARAMS_CNT;
                break;
        #endif
        #ifdef WOLFPKCS11_HKDF
            case CKK_HKDF:
        #endif
        #ifndef NO_AES
            case CKK_AES:
        #endif
            case CKK_GENERIC_SECRET:
                attrs = secretKeyParams;
                cnt = SECRET_KEY_PARAMS_CNT;
                break;
            default:
                (void)len;
                return CKR_OBJECT_HANDLE_INVALID;
        }
    }

    for (i = 0; i < cnt; i++) {
        for (j = 0; j < (int)ulCount; j++) {
            if (attrs[i] == pTemplate[j].type) {
                attrsFound = 1;
                data[i] = (unsigned char*)pTemplate[j].pValue;
                if (data[i] == NULL)
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                len[i] = (int)pTemplate[j].ulValueLen;
                break;
            }
        }
    }

    if (newObject == CK_TRUE || attrsFound == 1) {
        if (objClass == CKO_CERTIFICATE) {
            ret = WP11_Object_SetCert(obj, data, len);
        }
#ifdef WOLFPKCS11_NSS
        else if (objClass == CKO_NSS_TRUST) {
            ret = WP11_Object_SetTrust(obj, data, len);
        }
#endif
        else {
            /* Set the value and length of key specific attributes
            * Old key data is cleared.
            */
            switch (type) {
        #ifndef NO_RSA
                case CKK_RSA:
                    ret = WP11_Object_SetRsaKey(obj, data, len);
                    break;
        #endif
        #ifdef HAVE_ECC
                case CKK_EC:
                    ret = WP11_Object_SetEcKey(obj, data, len);
                    break;
        #endif
        #ifndef NO_DH
                case CKK_DH:
                    ret = WP11_Object_SetDhKey(obj, data, len);
                    break;
        #endif
        #ifndef NO_AES
                case CKK_AES:
        #endif
        #ifdef WOLFPKCS11_HKDF
                case CKK_HKDF:
        #endif
                case CKK_GENERIC_SECRET:
                    ret = WP11_Object_SetSecretKey(obj, data, len);
                    break;
                default:
                    break;
            }
        }
        if (ret == MEMORY_E)
            return CKR_DEVICE_MEMORY;
        if (ret != 0)
            return CKR_FUNCTION_FAILED;
    }

    /* Set remaining attributes - key specific attributes ignored. */
    for (i = 0; i < (int)ulCount; i++) {
        attr = &pTemplate[i];
        /* Cannot change sensitive from true to false */
        if (attr->type == CKA_SENSITIVE) {
            rv = WP11_Object_GetAttr(obj, CKA_SENSITIVE, &getVar, &getVarLen);
            if (rv != CKR_OK)
                return rv;

            if ((getVar == CK_TRUE) && (*(CK_BBOOL*)attr->pValue == CK_FALSE))
                return CKR_ATTRIBUTE_READ_ONLY;
        }
        ret = WP11_Object_SetAttr(obj, attr->type, (byte*)attr->pValue,
                                                              attr->ulValueLen);
        if (ret == BAD_FUNC_ARG)
            return CKR_ATTRIBUTE_VALUE_INVALID;
        else if (ret == BUFFER_E)
            return CKR_BUFFER_TOO_SMALL;
        else if (ret != 0)
            return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

/**
 * New Object object.
 *
 * @param  session    [in]   Session object.
 * @param  keyType    [in]   Type of key object.
 * @param  keyClass   [in]   Class of key object.
 * @param  pTemplate  [in]   Array of attributes to create object with.
 * @param  ulCount    [in]   Count of elements in array.
 * @param  object     [out]  New Object object.
 * @return  CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when setting an attribute fails.
 *          CKR_OK on success.
 */
static CK_RV NewObject(WP11_Session* session, CK_KEY_TYPE keyType,
                       CK_OBJECT_CLASS keyClass, CK_ATTRIBUTE_PTR pTemplate,
                       CK_ULONG ulCount, WP11_Object** object)
{
    int ret;
    CK_RV rv;
    WP11_Object* obj = NULL;

    ret = WP11_Object_New(session, keyType, &obj);
    if (ret == MEMORY_E)
        return CKR_DEVICE_MEMORY;
    if (ret != 0)
        return CKR_FUNCTION_FAILED;

    ret = WP11_Object_SetClass(obj, keyClass);
    if (ret != 0)
        return CKR_FUNCTION_FAILED;

    rv = SetAttributeValue(session, obj, pTemplate, ulCount, CK_TRUE);
    if (rv != CKR_OK) {
        WP11_Object_Free(obj);
        return rv;
    }

    switch(keyClass) {
        case CKO_PRIVATE_KEY:
        case CKO_SECRET_KEY:
        case CKO_PUBLIC_KEY:
            rv = SetAttributeDefaults(obj, keyClass, pTemplate, ulCount);
            break;
        default:
            /* For other types, such as potential CKO_DATA, not needed */
            rv = CKR_OK;
            break;
    }
    if (rv != CKR_OK) {
        WP11_Object_Free(obj);
        return rv;
    }

    *object = obj;

    return CKR_OK;
}

/**
 * Add an object to the session.
 *
 * @param  session    [in]   Session object.
 * @param  object     [in]   Object object.
 * @param  pTemplate  [in]   Array of attributes.
 * @param  ulCount    [in]   Count of elements in array.
 * @param  phKey      [out]  Handle to new key object.
 * @return  CKR_ATTRIBUTE_VALUE_INVALID when attribute value is not valid for
 *          data type.
 *          CKR_FUNCTION_FAILED when setting an attribute fails.
 *          CKR_OK on success.
 */
static CK_RV AddObject(WP11_Session* session, WP11_Object* object,
                       CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                       CK_OBJECT_HANDLE_PTR phKey)
{
    int ret;
    CK_ATTRIBUTE* attr;
    int onToken = 0;

    FindAttributeType(pTemplate, ulCount, CKA_TOKEN, &attr);
    if (attr != NULL) {
        if (attr->pValue == NULL)
            return CKR_ATTRIBUTE_VALUE_INVALID;
        if (attr->ulValueLen != sizeof(CK_BBOOL))
            return CKR_ATTRIBUTE_VALUE_INVALID;
        onToken = *(CK_BBOOL*)attr->pValue;
    }

    ret = WP11_Session_AddObject(session, onToken, object);
    if (ret != 0)
        return CKR_FUNCTION_FAILED;

    *phKey = WP11_Object_GetHandle(object);

    return CKR_OK;
}

#ifndef NO_RSA
/**
 * Create an RSA private key object in the session or on the token associated with the session.
 *
 * @param  session    [in]   Handle of session.
 * @param  pTemplate  [in]   Template of attributes for object.
 * @param  ulCount    [in]   Number of attribute triplets in template.
 * @param  derBuf     [in]   DER-encoded private key
 * @param  derLen     [in]   Length of the DER-encoded key data
 * @param  phKey      [out]  pointer to hold the handle to the new key object
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pTemplate or phObject is NULL.
 *          CKR_SESSION_READ_ONLY when the session cannot create objects.
 *          CKR_TEMPLATE_INCOMPLETE when CKA_KEY_TYPE is missing.
 *          CKR_ATTRIBUTE_VALUE_INVALID when an attribute has invalid value or
 *          length.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when creating the object fails.
 *          CKR_WRAPPED_KEY_INVALID when DER-encoded key data isn't valid
 *          CKR_OK on success.
 */
static CK_RV AddRSAPrivateKeyObject(WP11_Session* session,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, byte* derBuf, CK_ULONG derLen,
    CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv;
    WP11_Object* privKeyObject = NULL;

    *phKey = CK_INVALID_HANDLE;

    rv = NewObject(session, CKK_RSA, CKO_PRIVATE_KEY,
                   pTemplate, ulCount,
                   &privKeyObject);
    if (rv != CKR_OK)
        return rv;

    if (WP11_Rsa_ParsePrivKey(derBuf, (word32)derLen, privKeyObject) != 0 ) {
        rv = CKR_WRAPPED_KEY_INVALID;
        goto err_out;
    }

    rv = AddObject(session, privKeyObject, pTemplate, ulCount, phKey);

    /* Some other libraries create a public key object along with private key.
     * We'll do that when WOLFPKCS11_KEYPAIR_GEN_COMMON_LABEL is defined.
     */
#ifdef WOLFPKCS11_KEYPAIR_GEN_COMMON_LABEL
    {
        const int TOKEN_IDX = 0;
        const int LABEL_IDX = 1;

        WP11_Object* pubKeyObject = NULL;
        CK_ATTRIBUTE* attr = NULL;
        CK_BBOOL trueVal = CK_TRUE;
        CK_BBOOL falseVal = CK_TRUE;

        CK_OBJECT_HANDLE hPub;

        CK_ATTRIBUTE pubt[] = {
                {CKA_TOKEN,    NULL, sizeof(CK_BBOOL)},
                {CKA_LABEL,    NULL, 0},
                {CKA_WRAP,    &falseVal, sizeof(falseVal)},
                {CKA_VERIFY,  &trueVal, sizeof(trueVal)},
                {CKA_ENCRYPT, &trueVal,  sizeof(trueVal)}
        };

        if (rv != CKR_OK)
            goto err_out;

        FindAttributeType(pTemplate, ulCount, CKA_TOKEN, &attr);
        if (attr != NULL)
            if (attr->pValue != NULL && attr->ulValueLen == sizeof(CK_BBOOL))
                pubt[TOKEN_IDX].pValue = attr->pValue;


        FindAttributeType(pTemplate, ulCount, CKA_LABEL, &attr);
        if (attr != NULL) {
            if (attr->pValue != NULL && attr->ulValueLen != 0) {
                pubt[LABEL_IDX].pValue = attr->pValue;
                pubt[LABEL_IDX].ulValueLen = attr->ulValueLen;
            }
        }

        rv = NewObject(session, CKK_RSA, CKO_PUBLIC_KEY,
                       pubt, sizeof(pubt) / sizeof(CK_ATTRIBUTE),
                       &pubKeyObject);

        if (rv != CKR_OK)
            goto err_out;

        if (WP11_Rsa_PrivKey2PubKey(privKeyObject, pubKeyObject, derBuf,
                                                         (word32)derLen) == 0) {
            rv = AddObject(session, pubKeyObject, pubt,
                sizeof(pubt) / sizeof(CK_ATTRIBUTE), &hPub);
            if (rv != CKR_OK) {
                WP11_Object_Free(pubKeyObject);
            }
        }
        else {
            rv = CKR_WRAPPED_KEY_INVALID;
            WP11_Object_Free(pubKeyObject);
        }
    }
#endif

err_out:
    if (rv != CKR_OK) {
        if (*phKey != CK_INVALID_HANDLE) {
            WP11_Session_RemoveObject(session, privKeyObject);
            *phKey = CK_INVALID_HANDLE;
        }
        if (privKeyObject != NULL) {
            WP11_Object_Free(privKeyObject);
        }
    }

    return rv;
}
#endif

/**
 * Create an object in the session or on the token associated with the session.
 *
 * @param  hSession   [in]   Handle of session.
 * @param  pTemplate  [in]   Template of attributes for object.
 * @param  ulCount    [in]   Number of attribute triplets in template.
 * @param  object     [out]  New Object object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pTemplate or phObject is NULL.
 *          CKR_SESSION_READ_ONLY when the session cannot create objects.
 *          CKR_TEMPLATE_INCOMPLETE when CKA_KEY_TYPE is missing.
 *          CKR_ATTRIBUTE_VALUE_INVALID when an attribute has invalid value or
 *          length.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when creating the object fails.
 *          CKR_OK on success.
 */
static CK_RV CreateObject(WP11_Session* session, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount, WP11_Object** object)
{
    CK_RV rv;
    CK_ULONG objType = -1;
    CK_OBJECT_CLASS objectClass = -1;
    CK_ATTRIBUTE* attr;

    FindAttributeType(pTemplate, ulCount, CKA_CLASS, &attr);
    if (attr != NULL) {
        if (attr->pValue == NULL)
            return CKR_ATTRIBUTE_VALUE_INVALID;
        if (attr->ulValueLen != sizeof(CK_OBJECT_CLASS))
            return CKR_ATTRIBUTE_VALUE_INVALID;
        objectClass = *(CK_OBJECT_CLASS*)attr->pValue;
    }

    if (objectClass == CKO_CERTIFICATE) {
        FindAttributeType(pTemplate, ulCount, CKA_CERTIFICATE_TYPE, &attr);
        if (attr == NULL)
            return CKR_TEMPLATE_INCOMPLETE;
        if (attr->pValue == NULL)
            return CKR_ATTRIBUTE_VALUE_INVALID;
        if (attr->ulValueLen != sizeof(CK_ULONG))
            return CKR_ATTRIBUTE_VALUE_INVALID;
        objType = *(CK_ULONG*)attr->pValue;
        if (objType != CKC_X_509 && objType != CKC_X_509_ATTR_CERT &&
            objType != CKC_WTLS) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }
    else if (objectClass == CKO_DATA) {
        FindAttributeType(pTemplate, ulCount, CKA_VALUE, &attr);
        if (attr == NULL)
            return CKR_TEMPLATE_INCOMPLETE;
        objType = CKK_HKDF;
    }
#ifdef WOLFPKCS11_NSS
    else if (objectClass == CKO_NSS_TRUST) {
        FindAttributeType(pTemplate, ulCount, CKA_ISSUER, &attr);
        if (attr == NULL)
            return CKR_TEMPLATE_INCOMPLETE;
        FindAttributeType(pTemplate, ulCount, CKA_SERIAL_NUMBER, &attr);
        if (attr == NULL)
            return CKR_TEMPLATE_INCOMPLETE;
        FindAttributeType(pTemplate, ulCount, CKA_CERT_SHA1_HASH, &attr);
        if (attr == NULL)
            return CKR_TEMPLATE_INCOMPLETE;
        FindAttributeType(pTemplate, ulCount, CKA_CERT_MD5_HASH, &attr);
        if (attr == NULL)
            return CKR_TEMPLATE_INCOMPLETE;
        objType = CKK_NSS_TRUST;
    }
#endif
    else {
        FindAttributeType(pTemplate, ulCount, CKA_KEY_TYPE, &attr);
        if (attr == NULL)
            return CKR_TEMPLATE_INCOMPLETE;
        if (attr->pValue == NULL)
            return CKR_ATTRIBUTE_VALUE_INVALID;
        if (attr->ulValueLen != sizeof(CK_ULONG))
            return CKR_ATTRIBUTE_VALUE_INVALID;
        objType = *(CK_ULONG*)attr->pValue;

        if (objType != CKK_RSA && objType != CKK_EC && objType != CKK_DH &&
            objType != CKK_AES && objType != CKK_HKDF &&
            objType != CKK_GENERIC_SECRET) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    rv = NewObject(session, objType, objectClass, pTemplate, ulCount, object);

    return rv;
}

/**
 * Create an object in the session or on the token associated with the session.
 *
 * @param  hSession   [in]   Handle of session.
 * @param  pTemplate  [in]   Template of attributes for object.
 * @param  ulCount    [in]   Number of attribute triplets in template.
 * @param  phObject   [out]  Handle of object created.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pTemplate or phObject is NULL.
 *          CKR_SESSION_READ_ONLY when the session cannot create objects.
 *          CKR_TEMPLATE_INCOMPLETE when CKA_KEY_TYPE is missing.
 *          CKR_ATTRIBUTE_VALUE_INVALID when an attribute has invalid value or
 *          length.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when creating the object fails.
 *          CKR_OK on success.
 */
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    CK_RV rv;
    WP11_Session* session;
    WP11_Object* object;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pTemplate == NULL || phObject == NULL)
        return CKR_ARGUMENTS_BAD;
    if (!WP11_Session_IsRW(session))
        return CKR_SESSION_READ_ONLY;

    rv = CreateObject(session, pTemplate, ulCount, &object);
    if (rv != CKR_OK)
        return rv;
    rv = AddObject(session, object, pTemplate, ulCount, phObject);
    if (rv != CKR_OK)
        WP11_Object_Free(object);

    return rv;
}

/**
 * Copy the object in the session or on the token associated with the session.
 *
 * @param  hSession      [in]   Handle of session.
 * @param  hObject       [in]   Handle of object to copy.
 * @param  pTemplate     [in]   Template of attributes to copy.
 * @param  ulCount       [in]   Number of attribute triplets in template.
 * @param  phNewObject   [out]  Handle of object created.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pTemplate or phNewObject is NULL.
 *          CKR_SESSION_READ_ONLY when the session cannot create objects.
 *          CKR_OBJECT_HANDLE_INVALID when handle is not to a valid object.
 *          CKR_TEMPLATE_INCOMPLETE when CKA_KEY_TYPE is missing.
 *          CKR_ATTRIBUTE_VALUE_INVALID when an attribute has invalid value or
 *          length.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when creating the object fails.
 *          CKR_BUFFER_TOO_SMALL when an attributes length is too small for the
 *          value.
 *          CK_UNAVAILABLE_INFORMATION when an attribute type is not supported.
 *          CKR_OK on success.
 */
CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject)
{
    int ret;
    CK_RV rv;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    WP11_Object* newObj = NULL;
    CK_ATTRIBUTE* attr;
    CK_KEY_TYPE keyType;
    int onToken = 0;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pTemplate == NULL || phNewObject == NULL)
        return CKR_ARGUMENTS_BAD;
    if (!WP11_Session_IsRW(session))
        return CKR_SESSION_READ_ONLY;

    /* Need key type and whether object is to be on the token to create a new
     * object. Get the object type from original object and where to store
     * new object from template.
     */
    ret = WP11_Object_Find(session, hObject, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;
    keyType = WP11_Object_GetType(obj);

    FindAttributeType(pTemplate, ulCount, CKA_TOKEN, &attr);
    if (attr != NULL) {
        if (attr->pValue == NULL)
            return CKR_ATTRIBUTE_VALUE_INVALID;
        if (attr->ulValueLen != sizeof(CK_BBOOL))
            return CKR_ATTRIBUTE_VALUE_INVALID;
        onToken = *(CK_BBOOL*)attr->pValue;
    }

    ret = WP11_Object_New(session, keyType, &newObj);
    if (ret == MEMORY_E)
        return CKR_DEVICE_MEMORY;
    if (ret != 0)
        return CKR_FUNCTION_FAILED;

    /* Use get and set attribute value to fill in object. */
    rv = C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
    if (rv != CKR_OK) {
        WP11_Object_Free(newObj);
        return rv;
    }
    rv = SetAttributeValue(session, newObj, pTemplate, ulCount, CK_TRUE);
    if (rv != CKR_OK) {
        WP11_Object_Free(newObj);
        return rv;
    }

    ret = WP11_Session_AddObject(session, onToken, newObj);
    if (ret != 0) {
        WP11_Object_Free(newObj);
        return CKR_FUNCTION_FAILED;
    }

    *phNewObject = WP11_Object_GetHandle(newObj);

    return CKR_OK;
}

/**
 * Destroy object in session or on token.
 *
 * @param  hSession  [in]  Handle of session.
 * @param  hObject   [in]  Handle of object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_SESSION_READ_ONLY when the session cannot create objects.
 *          CKR_OBJECT_HANDLE_INVALID when handle is not to a valid object.
 *          CKR_OK on success.
 */
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
                      CK_OBJECT_HANDLE hObject)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (!WP11_Session_IsRW(session))
        return CKR_SESSION_READ_ONLY;

    ret = WP11_Object_Find(session, hObject, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    WP11_Session_RemoveObject(session, obj);
    WP11_Object_Free(obj);

    return CKR_OK;
}

/**
 * Get the size of an specific object.
 * Not supported.
 *
 * @param  hSession  [in]   Handle of session.
 * @param  hObject   [in]   Handle of object.
 * @param  pulSize   [out]  Size in bytes of object on the token.
 *                          CK_UNAVAILABLE_INFORMATION is returned to indicate
 *                          this operation is not supported.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pulSize is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when handle is not to a valid object.
 *          CKR_OK on success.
 */
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,
                      CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pulSize == NULL)
        return CKR_ARGUMENTS_BAD;

    ret = WP11_Object_Find(session, hObject, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    *pulSize = CK_UNAVAILABLE_INFORMATION;

    return CKR_OK;
}


/**
 * Get the values of the attributes from the object.
 *
 * @param  hSession   [in]  Handle of session.
 * @param  pTemplate  [in]  Template of attributes for object.
 * @param  ulCount    [in]  Number of attribute triplets in template.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pTemplate is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when handle is not to a valid object.
 *          CKR_ATTRIBUTE_TYPE_INVALID if the attribute type is not supported.
 *          CKR_ATTRIBUTE_VALUE_INVALID if value is not valid for data type.
 *          CKR_BUFFER_TOO_SMALL if an attribute length is too short.
 *          CK_UNAVAILABLE_INFORMATION when an attribute type is not supported
 *          for retrieval.
 *          CKR_FUNCTION_FAILED when getting a value fails.
 *          CKR_OK on success.
 */
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    int ret;
    CK_RV rv;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    CK_ATTRIBUTE* attr;
    int i;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pTemplate == NULL)
        return CKR_ARGUMENTS_BAD;

    ret = WP11_Object_Find(session, hObject, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    /* Check the value and lengths of attributes based on data type. */
    rv = CheckAttributes(pTemplate, ulCount, 0);
    if (rv != CKR_OK)
        return rv;

    for (i = 0; i < (int)ulCount; i++) {
        attr = &pTemplate[i];

        ret = WP11_Object_GetAttr(obj, attr->type, (byte*)attr->pValue,
                                                             &attr->ulValueLen);
        if (ret == BAD_FUNC_ARG)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        else if (ret == BUFFER_E)
            return CKR_BUFFER_TOO_SMALL;
        else if (ret == NOT_AVAILABLE_E)
            return CK_UNAVAILABLE_INFORMATION;
        else if (ret == CKR_ATTRIBUTE_SENSITIVE)
            rv = ret;
        else if (ret != 0)
            return CKR_FUNCTION_FAILED;
    }

    return rv;
}

/**
 * Set the values of the attributes into the object.
 *
 * @param  hSession   [in]  Handle of session.
 * @param  hObject    [in]  Handle of object to set value against.
 * @param  pTemplate  [in]  Template of attributes set against object.
 * @param  ulCount    [in]  Number of attribute triplets in template.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pTemplate is NULL.
 *          CKR_SESSION_READ_ONLY when the session cannot modify objects.
 *          CKR_OBJECT_HANDLE_INVALID when handle is not to a valid object.
 *          CKR_ATTRIBUTE_TYPE_INVALID if the attribute type is not supported.
 *          CKR_ATTRIBUTE_VALUE_INVALID if value is not valid for data type.
 *          CKR_BUFFER_TOO_SMALL if an attribute length is too short.
 *          CK_UNAVAILABLE_INFORMATION when an attribute type is not supported
 *          for modification.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when getting a value fails.
 *          CKR_OK on success.
 */
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pTemplate == NULL)
        return CKR_ARGUMENTS_BAD;
    if (!WP11_Session_IsRW(session))
        return CKR_SESSION_READ_ONLY;

    ret = WP11_Object_Find(session, hObject, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    return SetAttributeValue(session, obj, pTemplate, ulCount, CK_FALSE);
}

/**
 * Initialize the finding of an object associated with the session.
 * All matching objects are found, up to a limit, by this call.
 *
 * @param  hSession   [in]  Handle of session.
 * @param  pTemplate  [in]  Template of attributes match against object.
 * @param  ulCount    [in]  Number of attribute triplets in template.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pTemplate is NULL.
 *          CKR_OPERATION_ACTIVE when last find operation on session has not
 *          been finalized.
 *          CKR_ATTRIBUTE_VALUE_INVALID when attribute value is not valid for
 *          data type.
 *          CKR_OK on success.
 */
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    WP11_Session* session;
    CK_ATTRIBUTE* attr;
    int onToken = 1;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pTemplate == NULL)
        return CKR_ARGUMENTS_BAD;

    if (WP11_Session_FindInit(session) != 0)
        return CKR_OPERATION_ACTIVE;

    FindAttributeType(pTemplate, ulCount, CKA_TOKEN, &attr);
    if (attr != NULL) {
        if (attr->pValue == NULL)
            return CKR_ATTRIBUTE_VALUE_INVALID;
        if (attr->ulValueLen != sizeof(CK_BBOOL))
            return CKR_ATTRIBUTE_VALUE_INVALID;
        onToken = *(CK_BBOOL*)attr->pValue;
    }

    WP11_Session_Find(session, onToken, pTemplate, ulCount);

    return CKR_OK;
}

/**
 * Return next handles to found objects.
 * Object match the criteria set in the initialization call.
 *
 * @param  hSession          [in]   Handle of session.
 * @param  phObject          [in]   Array to hold object handles.
 * @param  ulMaxObjectCount  [in]   Number of entries in array.
 * @param  pulObjectCount    [out]  Number of handles set into array.
 *                                  0 when no more handles available.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when phObject or pulObjectCount is NULL.
 *          CKR_OK on success.
 */
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
                    CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount,
                    CK_ULONG_PTR pulObjectCount)
{
    int i;
    CK_OBJECT_HANDLE handle;
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (phObject == NULL || pulObjectCount == NULL)
        return CKR_ARGUMENTS_BAD;

    for (i = 0; i < (int)ulMaxObjectCount; i++) {
        if (WP11_Session_FindGet(session, &handle) == FIND_NO_MORE_E)
            break;
        phObject[i] = handle;
    }
    *pulObjectCount = i;

    return CKR_OK;
}

/**
 * Finalize the object finding operation.
 * Must be called before another find operation on the session is initialized.
 *
 * @param  hSession  [in]   Handle of session.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_OK on success.
 */
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;

    WP11_Session_FindFinal(session);

    return CKR_OK;
}


/**
 * Initialize encryption operation.
 *
 * @param  hSession    [in]  Handle of session.
 * @param  pMechanism  [in]  Type of operation to perform with parameters.
 * @param  hKey        [in]  Handle to key object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when key object handle is not valid.
 *          CKR_KEY_TYPE_INCONSISTENT when the key type is not valid for the
 *          mechanism (operation).
 *          CKR_MECHANISM_PARAM_INVALID when mechanism's parameters are not
 *          valid for the operation.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when initializing fails.
 *          CKR_OK on success.
 */
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    CK_KEY_TYPE type;
    int init;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;

    ret = WP11_Object_Find(session, hKey, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    type = WP11_Object_GetType(obj);
    switch (pMechanism->mechanism) {
#ifndef NO_RSA
        case CKM_RSA_X_509:
            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            init = WP11_INIT_RSA_X_509_ENC;
            break;

        case CKM_RSA_PKCS:
            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            init = WP11_INIT_RSA_PKCS_ENC;
            break;

    #ifndef WC_NO_RSA_OAEP
        case CKM_RSA_PKCS_OAEP: {
            CK_RSA_PKCS_OAEP_PARAMS* params;

            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            params = (CK_RSA_PKCS_OAEP_PARAMS*)pMechanism->pParameter;
            if (params->source != CKZ_DATA_SPECIFIED)
                return CKR_MECHANISM_PARAM_INVALID;

            ret = WP11_Session_SetOaepParams(session, params->hashAlg,
                params->mgf, (byte*)params->pSourceData,
                (int)params->ulSourceDataLen);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init = WP11_INIT_RSA_PKCS_OAEP_ENC;
            break;
        }
    #endif
#endif

#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        case CKM_AES_CBC:
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != AES_IV_SIZE)
                return CKR_MECHANISM_PARAM_INVALID;
            ret = WP11_Session_SetCbcParams(session,
                (unsigned char*)pMechanism->pParameter, 1, obj);
            if (ret == MEMORY_E)
                return CKR_DEVICE_MEMORY;
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init = WP11_INIT_AES_CBC_ENC;
            break;

        case CKM_AES_CBC_PAD:
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != AES_IV_SIZE)
                return CKR_MECHANISM_PARAM_INVALID;
            ret = WP11_Session_SetCbcParams(session,
                (unsigned char*)pMechanism->pParameter, 1, obj);
            if (ret == MEMORY_E)
                return CKR_DEVICE_MEMORY;
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init = WP11_INIT_AES_CBC_PAD_ENC;
            break;
    #endif

    #ifdef HAVE_AESCTR
        case CKM_AES_CTR: {
            CK_AES_CTR_PARAMS* params;

            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_AES_CTR_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            params = (CK_AES_CTR_PARAMS*)pMechanism->pParameter;
            ret = WP11_Session_SetCtrParams(session, params->ulCounterBits,
                                            params->cb, obj);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init = WP11_INIT_AES_CTR_ENC;
            break;
        }
    #endif

    #ifdef HAVE_AES_KEYWRAP
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_PAD: {
            byte* iv = NULL;
            word32 ivLen = 0;

            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL) {
                if (pMechanism->ulParameterLen != 8)
                    return CKR_MECHANISM_PARAM_INVALID;
                iv = (byte*)pMechanism->pParameter;
                ivLen = 8;
            }
            else if (pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }

            ret = WP11_Session_SetAesWrapParams(session, iv, ivLen, obj, 1);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init = WP11_INIT_AES_KEYWRAP_ENC;
            break;
        }
    #endif

    #ifdef HAVE_AESGCM
        case CKM_AES_GCM: {
             CK_GCM_PARAMS* params;

            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            params = (CK_GCM_PARAMS*)pMechanism->pParameter;
            ret = WP11_Session_SetGcmParams(session, params->pIv,
                                             (int)params->ulIvLen, params->pAAD,
                                             (int)params->ulAADLen,
                                             (int)params->ulTagBits);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init = WP11_INIT_AES_GCM_ENC;
            break;
        }
    #endif

    #ifdef HAVE_AESCCM
        case CKM_AES_CCM: {
             CK_CCM_PARAMS* params;

            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_CCM_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            params = (CK_CCM_PARAMS*)pMechanism->pParameter;
            ret = WP11_Session_SetCcmParams(session,
                                            (int)params->ulDataLen,
                                            params->pIv, (int)params->ulIvLen,
                                            params->pAAD, (int)params->ulAADLen,
                                            (int)params->ulMacLen);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init = WP11_INIT_AES_CCM_ENC;
            break;
        }
    #endif

    #ifdef HAVE_AESECB
        case CKM_AES_ECB: {
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != 0)
                return CKR_MECHANISM_PARAM_INVALID;

            init = WP11_INIT_AES_ECB_ENC;
            break;
        }
    #endif

    #ifdef HAVE_AESCTS
        case CKM_AES_CTS:
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != AES_IV_SIZE)
                return CKR_MECHANISM_PARAM_INVALID;
            ret = WP11_Session_SetCtsParams(session,
                (unsigned char*)pMechanism->pParameter, 1, obj);
            if (ret == MEMORY_E)
                return CKR_DEVICE_MEMORY;
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init = WP11_INIT_AES_CTS_ENC;
            break;
    #endif
#endif
        default:
            (void)type;
            return CKR_MECHANISM_INVALID;
    }

    WP11_Session_SetMechanism(session, pMechanism->mechanism);
    WP11_Session_SetObject(session, obj);
    WP11_Session_SetOpInitialized(session, init);

    return CKR_OK;
}

/**
 * Encrypt single-part data.
 *
 * @param  hSession             [in]      Handle of session.
 * @param  pData                [in]      Data to encrypt.
 * @param  ulDataLen            [in]      Length of data in bytes.
 * @param  pEncryptedData       [in]      Buffer to hold encrypted data.
 *                                        NULL indicates length required.
 * @param  pulEncryptedDataLen  [in,out]  On in, length of buffer in bytes.
 *                                        On out, length of encrypted data in
 *                                        bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pData or pulEncryptedDataLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_EncryptInit has not been
 *          successfully called.
 *          CKR_BUFFER_TOO_SMALL when the output length is too small for
 *          encrypted data.
 *          CKR_FUNCTION_FAILED when encrypting failed.
 *          CKR_OK on success.
 */
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    word32 encDataLen;
    CK_MECHANISM_TYPE mechanism;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pData == NULL || pulEncryptedDataLen == NULL)
        return CKR_ARGUMENTS_BAD;

    /* Key the key for the encryption operation. */
    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_RSA
        case CKM_RSA_X_509:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_RSA_X_509_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encDataLen = WP11_Rsa_KeyLen(obj);
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = encDataLen;
                return CKR_OK;
            }
            if (encDataLen > (word32)*pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_Rsa_PublicEncrypt(pData, (int)ulDataLen, pEncryptedData,
                                                 &encDataLen, obj,
                                                 WP11_Session_GetSlot(session));
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
        case CKM_RSA_PKCS:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_RSA_PKCS_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encDataLen = WP11_Rsa_KeyLen(obj);
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = encDataLen;
                return CKR_OK;
            }
            if (encDataLen > (word32)*pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_RsaPkcs15_PublicEncrypt(pData, (int)ulDataLen,
                                               pEncryptedData, &encDataLen, obj,
                                               WP11_Session_GetSlot(session));
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
    #ifndef WC_NO_RSA_OAEP
        case CKM_RSA_PKCS_OAEP:
            if (!WP11_Session_IsOpInitialized(session,
                                                 WP11_INIT_RSA_PKCS_OAEP_ENC)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }

            encDataLen = WP11_Rsa_KeyLen(obj);
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = encDataLen;
                return CKR_OK;
            }
            if (encDataLen > (word32)*pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_RsaOaep_PublicEncrypt(pData, (int)ulDataLen,
                                               pEncryptedData, &encDataLen, obj,
                                               session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
    #endif
#endif
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        case CKM_AES_CBC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CBC_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encDataLen = (word32)ulDataLen;
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = encDataLen;
                return CKR_OK;
            }
            if (encDataLen > (word32)*pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCbc_Encrypt(pData, (int)ulDataLen, pEncryptedData,
                                                          &encDataLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
        case CKM_AES_CBC_PAD:
            if (!WP11_Session_IsOpInitialized(session,
                                                   WP11_INIT_AES_CBC_PAD_ENC)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }

            /* PKCS#5 pad makes the output a multiple of 16 */
            encDataLen = (word32)((ulDataLen + WC_AES_BLOCK_SIZE - 1) /
                        WC_AES_BLOCK_SIZE) * WC_AES_BLOCK_SIZE;
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = encDataLen;
                return CKR_OK;
            }
            if (encDataLen > (word32)*pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCbcPad_Encrypt(pData, (int)ulDataLen, pEncryptedData,
                                                          &encDataLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
    #endif
    #ifdef HAVE_AESCTR
        case CKM_AES_CTR:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTR_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = ulDataLen;
                return CKR_OK;
            }
            if (ulDataLen > *pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            encDataLen = (word32)*pulEncryptedDataLen;
            ret = WP11_AesCtr_Do(pData, (word32)ulDataLen, pEncryptedData,
                                 &encDataLen, session);
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
    #endif
    #ifdef HAVE_AESGCM
        case CKM_AES_GCM:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_GCM_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encDataLen = (word32)ulDataLen +
                                            WP11_AesGcm_GetTagBits(session) / 8;
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = encDataLen;
                return CKR_OK;
            }
            if (encDataLen > (word32)*pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesGcm_Encrypt(pData, (int)ulDataLen, pEncryptedData,
                                                     &encDataLen, obj, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
    #endif
    #ifdef HAVE_AESCCM
        case CKM_AES_CCM:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CCM_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encDataLen = (word32)ulDataLen +
                                            WP11_AesCcm_GetMacLen(session);
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = encDataLen;
                return CKR_OK;
            }
            if (encDataLen > (word32)*pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCcm_Encrypt(pData, (int)ulDataLen, pEncryptedData,
                                      &encDataLen, obj, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
    #endif
    #ifdef HAVE_AESECB
        case CKM_AES_ECB:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_ECB_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encDataLen = (word32)ulDataLen;
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = encDataLen;
                return CKR_OK;
            }
            if (encDataLen > (word32)*pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesEcb_Encrypt(pData, (int)ulDataLen, pEncryptedData,
                                      &encDataLen, obj, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
    #endif
    #ifdef HAVE_AESCTS
        case CKM_AES_CTS:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTS_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encDataLen = (word32)*pulEncryptedDataLen;
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = ulDataLen;
                return CKR_OK;
            }
            if (ulDataLen > *pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCts_Encrypt(pData, (int)ulDataLen, pEncryptedData,
                                                          &encDataLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
    #endif
    #ifdef HAVE_AES_KEYWRAP
        case CKM_AES_KEY_WRAP:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_KEYWRAP_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            /* AES Key Wrap adds 8 bytes for the integrity check value */
            encDataLen = (word32)(ulDataLen + KEYWRAP_BLOCK_SIZE);
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = encDataLen;
                return CKR_OK;
            }
            if (encDataLen > (word32)*pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesKeyWrap_Encrypt(pData, (word32)ulDataLen,
                                          pEncryptedData, &encDataLen, session);
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
        case CKM_AES_KEY_WRAP_PAD: {
            byte* paddedData = NULL;
            byte padding = KEYWRAP_BLOCK_SIZE - (ulDataLen % KEYWRAP_BLOCK_SIZE);

            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_KEYWRAP_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            /* AES Key Wrap Pad adds up to 16 bytes for the integrity check
             * value and padding */
            encDataLen = (word32)(ulDataLen + KEYWRAP_BLOCK_SIZE + padding);
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = encDataLen;
                return CKR_OK;
            }
            if (encDataLen > (word32)*pulEncryptedDataLen)
                return CKR_BUFFER_TOO_SMALL;
            paddedData = (byte*)XMALLOC(ulDataLen + padding, NULL,
                                        DYNAMIC_TYPE_TMP_BUFFER);
            if (paddedData == NULL)
                return CKR_DEVICE_MEMORY;
            XMEMCPY(paddedData, pData, ulDataLen);
            XMEMSET(paddedData + ulDataLen, padding, padding);

            ret = WP11_AesKeyWrap_Encrypt(paddedData, (word32)ulDataLen + padding,
                                          pEncryptedData, &encDataLen, session);
            XMEMSET(paddedData, 0, ulDataLen + padding);
            XFREE(paddedData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedDataLen = encDataLen;
            break;
        }
    #endif
#endif
        default:
            (void)ret;
            (void)encDataLen;
            (void)ulDataLen;
            (void)pEncryptedData;
            return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/**
 * Continue encrypting multi-part data.
 *
 * @param  hSession             [in]      Handle of session.
 * @param  pPart                [in]      Data to encrypt.
 * @param  ulPartLen            [in]      Length of data in bytes.
 * @param  pEncryptedPart       [in]      Buffer to hold encrypted data.
 *                                        NULL indicates length required.
 * @param  pulEncryptedPartLen  [in,out]  On in, length of buffer in bytes.
 *                                        On out, length of encrypted data in
 *                                        bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pPart or pulEncryptedPartLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_EncryptInit has not been
 *          successfully called.
 *          CKR_BUFFER_TOO_SMALL when the output length is too small for
 *          encrypted data.
 *          CKR_FUNCTION_FAILED when encrypting failed.
 *          CKR_OK on success.
 */
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    word32 encPartLen;
    CK_MECHANISM_TYPE mechanism;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pPart == NULL || pulEncryptedPartLen == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        case CKM_AES_CBC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CBC_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encPartLen = (word32)ulPartLen + WP11_AesCbc_PartLen(session);
            encPartLen &= ~0xf;
            if (pEncryptedPart == NULL) {
                *pulEncryptedPartLen = encPartLen;
                return CKR_OK;
            }
            if (encPartLen > (word32)*pulEncryptedPartLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCbc_EncryptUpdate(pPart, (int)ulPartLen,
                                                    pEncryptedPart, &encPartLen,
                                                    session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedPartLen = encPartLen;
            break;
        case CKM_AES_CBC_PAD:
            if (!WP11_Session_IsOpInitialized(session,
                                                   WP11_INIT_AES_CBC_PAD_ENC)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }

            encPartLen = (word32)ulPartLen + WP11_AesCbc_PartLen(session);
            encPartLen &= ~0xf;
            if (pEncryptedPart == NULL) {
                *pulEncryptedPartLen = encPartLen;
                return CKR_OK;
            }
            if (encPartLen > (word32)*pulEncryptedPartLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCbcPad_EncryptUpdate(pPart, (int)ulPartLen,
                                          pEncryptedPart, &encPartLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedPartLen = encPartLen;
            break;
    #endif
    #ifdef HAVE_AESCTR
        case CKM_AES_CTR:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTR_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pEncryptedPart == NULL) {
                *pulEncryptedPartLen = ulPartLen;
                return CKR_OK;
            }
            if (ulPartLen > *pulEncryptedPartLen)
                return CKR_BUFFER_TOO_SMALL;

            encPartLen = (word32)*pulEncryptedPartLen;
            ret = WP11_AesCtr_Update(pPart, (int)ulPartLen, pEncryptedPart,
                                     &encPartLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedPartLen = encPartLen;
            break;
    #endif
    #ifdef HAVE_AESGCM
        case CKM_AES_GCM:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_GCM_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encPartLen = (word32)ulPartLen;
            if (pEncryptedPart == NULL) {
                *pulEncryptedPartLen = encPartLen;
                return CKR_OK;
            }
            if (encPartLen > (word32)*pulEncryptedPartLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesGcm_EncryptUpdate(pPart, (int)ulPartLen,
                                               pEncryptedPart, &encPartLen, obj,
                                               session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedPartLen = encPartLen;
            break;
    #endif
    #ifdef HAVE_AESCTS
        case CKM_AES_CTS:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTS_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pEncryptedPart == NULL) {
                *pulEncryptedPartLen = ulPartLen + WC_AES_BLOCK_SIZE * 2;
                return CKR_OK;
            }

            encPartLen = (word32)*pulEncryptedPartLen;
            ret = WP11_AesCts_EncryptUpdate(pPart, (word32)ulPartLen,
                                          pEncryptedPart, &encPartLen, session);
            if (ret == BUFFER_E)
                return CKR_BUFFER_TOO_SMALL;
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulEncryptedPartLen = encPartLen;
            break;
    #endif
#endif
        default:
            (void)encPartLen;
            (void)ret;
            (void)ulPartLen;
            (void)pEncryptedPart;
            return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/**
 * Finishes encrypting multi-part data.
 *
 * @param  hSession                 [in]      Handle of session.
 * @param  pLastEncryptedPart       [in]      Buffer to hold encrypted data.
 *                                            NULL indicates length required.
 * @param  pulLastEncryptedPartLen  [in,out]  On in, length of buffer in bytes.
 *                                            On out, length of encrypted data
 *                                            in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pPart or pulEncryptedPartLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_EncryptInit has not been
 *          successfully called.
 *          CKR_BUFFER_TOO_SMALL when the output length is too small for
 *          encrypted data.
 *          CKR_FUNCTION_FAILED when encrypting failed.
 *          CKR_OK on success.
 */
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pLastEncryptedPart,
                     CK_ULONG_PTR pulLastEncryptedPartLen)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    word32 encPartLen;
    CK_MECHANISM_TYPE mechanism;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pulLastEncryptedPartLen == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        case CKM_AES_CBC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CBC_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encPartLen = WP11_AesCbc_PartLen(session);
            if (encPartLen != 0) {
                WP11_AesCbc_EncryptFinal(session);
                return CKR_DATA_LEN_RANGE;
            }
            *pulLastEncryptedPartLen = 0;
            if (pLastEncryptedPart == NULL)
                return CKR_OK;

            ret = WP11_AesCbc_EncryptFinal(session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            break;
        case CKM_AES_CBC_PAD:
            if (!WP11_Session_IsOpInitialized(session,
                                                   WP11_INIT_AES_CBC_PAD_ENC)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }

            encPartLen = 16;
            if (pLastEncryptedPart == NULL) {
                *pulLastEncryptedPartLen = encPartLen;
                return CKR_OK;
            }
            if (encPartLen > (word32)*pulLastEncryptedPartLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCbcPad_EncryptFinal(pLastEncryptedPart, &encPartLen,
                                                                       session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            break;
    #endif
    #ifdef HAVE_AESCTR
        case CKM_AES_CTR:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTR_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pLastEncryptedPart == NULL) {
                *pulLastEncryptedPartLen = 0;
                return CKR_OK;
            }

            ret = WP11_AesCtr_Final(session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulLastEncryptedPartLen = 0;
            break;
    #endif
    #ifdef HAVE_AESGCM
        case CKM_AES_GCM:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_GCM_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            encPartLen = WP11_AesGcm_GetTagBits(session) / 8;
            if (pLastEncryptedPart == NULL) {
                *pulLastEncryptedPartLen = encPartLen;
                return CKR_OK;
            }
            if (encPartLen > (word32)*pulLastEncryptedPartLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesGcm_EncryptFinal(pLastEncryptedPart, &encPartLen,
                                                                       session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulLastEncryptedPartLen = encPartLen;
            break;
    #endif
    #ifdef HAVE_AESCTS
        case CKM_AES_CTS:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTS_ENC))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pLastEncryptedPart == NULL) {
                *pulLastEncryptedPartLen = WC_AES_BLOCK_SIZE * 2;
                return CKR_OK;
            }

            encPartLen = (word32)*pulLastEncryptedPartLen;
            ret = WP11_AesCts_EncryptFinal(pLastEncryptedPart, &encPartLen,
                                           session);
            if (ret == BUFFER_E)
                return CKR_BUFFER_TOO_SMALL;
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulLastEncryptedPartLen = encPartLen;
            break;
    #endif
#endif
        default:
            (void)encPartLen;
            (void)ret;
            (void)pLastEncryptedPart;
            return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/**
 * Initialize decryption operation.
 *
 * @param  hSession    [in]  Handle of session.
 * @param  pMechanism  [in]  Type of operation to perform with parameters.
 * @param  hKey        [in]  Handle to key object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when key object handle is not valid.
 *          CKR_KEY_TYPE_INCONSISTENT when the key type is not valid for the
 *          mechanism (operation).
 *          CKR_MECHANISM_PARAM_INVALID when mechanism's parameters are not
 *          valid for the operation.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when initializing fails.
 *          CKR_OK on success.
 */
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    CK_KEY_TYPE type;
    int init;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;

    ret = WP11_Object_Find(session, hKey, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    type = WP11_Object_GetType(obj);
    switch (pMechanism->mechanism) {
#ifndef NO_RSA
        case CKM_RSA_X_509:
            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            init = WP11_INIT_RSA_X_509_DEC;
            break;
        case CKM_RSA_PKCS:
            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            init = WP11_INIT_RSA_PKCS_DEC;
            break;
    #ifndef WC_NO_RSA_OAEP
        case CKM_RSA_PKCS_OAEP: {
            CK_RSA_PKCS_OAEP_PARAMS* params;

            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            params = (CK_RSA_PKCS_OAEP_PARAMS*)pMechanism->pParameter;
            if (params->source != CKZ_DATA_SPECIFIED)
                return CKR_MECHANISM_PARAM_INVALID;

            ret = WP11_Session_SetOaepParams(session, params->hashAlg,
                params->mgf, (byte*)params->pSourceData,
                (int)params->ulSourceDataLen);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init = WP11_INIT_RSA_PKCS_OAEP_DEC;
            break;
        }
    #endif
#endif
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        case CKM_AES_CBC:
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != AES_IV_SIZE)
                return CKR_MECHANISM_PARAM_INVALID;
            ret = WP11_Session_SetCbcParams(session,
                (unsigned char*)pMechanism->pParameter, 0, obj);
            if (ret == MEMORY_E)
                return CKR_DEVICE_MEMORY;
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init = WP11_INIT_AES_CBC_DEC;
            break;
        case CKM_AES_CBC_PAD:
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != AES_IV_SIZE)
                return CKR_MECHANISM_PARAM_INVALID;
            ret = WP11_Session_SetCbcParams(session,
                (unsigned char*)pMechanism->pParameter, 0, obj);
            if (ret == MEMORY_E)
                return CKR_DEVICE_MEMORY;
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init = WP11_INIT_AES_CBC_PAD_DEC;
            break;
    #endif
    #ifdef HAVE_AESCTR
        case CKM_AES_CTR: {
            CK_AES_CTR_PARAMS* params;

            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_AES_CTR_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            params = (CK_AES_CTR_PARAMS*)pMechanism->pParameter;
            ret = WP11_Session_SetCtrParams(session, params->ulCounterBits,
                                            params->cb, obj);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init = WP11_INIT_AES_CTR_DEC;
            break;
        }
    #endif
    #ifdef HAVE_AESGCM
        case CKM_AES_GCM: {
            CK_GCM_PARAMS* params;

            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            params = (CK_GCM_PARAMS*)pMechanism->pParameter;
            ret = WP11_Session_SetGcmParams(session, params->pIv,
                                             (int)params->ulIvLen, params->pAAD,
                                             (int)params->ulAADLen,
                                             (int)params->ulTagBits);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init = WP11_INIT_AES_GCM_DEC;
            break;
        }
    #endif
    #ifdef HAVE_AESCCM
        case CKM_AES_CCM: {
            CK_CCM_PARAMS* params;

            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_CCM_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            params = (CK_CCM_PARAMS*)pMechanism->pParameter;
            ret = WP11_Session_SetCcmParams(session,
                                            (int)params->ulDataLen,
                                            params->pIv, (int)params->ulIvLen,
                                            params->pAAD, (int)params->ulAADLen,
                                            (int)params->ulMacLen);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init = WP11_INIT_AES_CCM_DEC;
            break;
        }
    #endif
    #ifdef HAVE_AESECB
        case CKM_AES_ECB: {
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != 0)
                return CKR_MECHANISM_PARAM_INVALID;

            init = WP11_INIT_AES_ECB_DEC;
            break;
        }
    #endif

    #ifdef HAVE_AESCTS
        case CKM_AES_CTS:
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != AES_IV_SIZE)
                return CKR_MECHANISM_PARAM_INVALID;
            ret = WP11_Session_SetCtsParams(session,
                (unsigned char*)pMechanism->pParameter, 0, obj);
            if (ret == MEMORY_E)
                return CKR_DEVICE_MEMORY;
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init = WP11_INIT_AES_CTS_DEC;
            break;
    #endif

    #ifdef HAVE_AES_KEYWRAP
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_PAD: {
            byte* iv = NULL;
            word32 ivLen = 0;

            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL) {
                if (pMechanism->ulParameterLen != 8)
                    return CKR_MECHANISM_PARAM_INVALID;
                iv = (byte*)pMechanism->pParameter;
                ivLen = 8;
            }
            else if (pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }

            ret = WP11_Session_SetAesWrapParams(session, iv, ivLen, obj, 0);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init = WP11_INIT_AES_KEYWRAP_DEC;
            break;
        }
    #endif

#endif
        default:
            (void)type;
            return CKR_MECHANISM_INVALID;
    }

    WP11_Session_SetMechanism(session, pMechanism->mechanism);
    WP11_Session_SetObject(session, obj);
    WP11_Session_SetOpInitialized(session, init);

    return CKR_OK;
}

/**
 * Decrypt single-part data.
 *
 * @param  hSession            [in]      Handle of session.
 * @param  pEncryptedData      [in]      Data to decrypt.
 * @param  ulEncryptedDataLen  [in]      Length of data in bytes.
 * @param  pData               [in]      Buffer to hold decrypted data.
 *                                       NULL indicates length required.
 * @param  pulDataLen          [in,out]  On in, length of buffer in bytes.
 *                                       On out, length of decrypted data in
 *                                       bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pEncryptedData or pulDataLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_DecryptInit has not been
 *          successfully called.
 *          CKR_BUFFER_TOO_SMALL when the output length is too small for
 *          decrypted data.
 *          CKR_FUNCTION_FAILED when decrypting failed.
 *          CKR_MECHANISM_INVALID when wrong initialization function was used.
 *          CKR_OK on success.
 */
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    word32 decDataLen;
    CK_MECHANISM_TYPE mechanism;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pEncryptedData == NULL || pulDataLen == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_RSA
        case CKM_RSA_X_509:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_RSA_X_509_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            decDataLen = WP11_Rsa_KeyLen(obj);
            if (pData == NULL) {
                *pulDataLen = decDataLen;
                return CKR_OK;
            }
            if (decDataLen > (word32)*pulDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_Rsa_PrivateDecrypt(pEncryptedData,
                                                 (int)ulEncryptedDataLen, pData,
                                                 &decDataLen, obj,
                                                 WP11_Session_GetSlot(session));
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulDataLen = decDataLen;
            break;
        case CKM_RSA_PKCS:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_RSA_PKCS_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            decDataLen = WP11_Rsa_KeyLen(obj);
            if (pData == NULL) {
                *pulDataLen = decDataLen;
                return CKR_OK;
            }
            if (decDataLen > (word32)*pulDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_RsaPkcs15_PrivateDecrypt(pEncryptedData,
                                                 (int)ulEncryptedDataLen, pData,
                                                 &decDataLen, obj,
                                                 WP11_Session_GetSlot(session));
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulDataLen = decDataLen;
            break;
    #ifndef WC_NO_RSA_OAEP
        case CKM_RSA_PKCS_OAEP:
            if (!WP11_Session_IsOpInitialized(session,
                                                 WP11_INIT_RSA_PKCS_OAEP_DEC)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }

            decDataLen = WP11_Rsa_KeyLen(obj);
            if (pData == NULL) {
                *pulDataLen = decDataLen;
                return CKR_OK;
            }
            if (decDataLen > (word32)*pulDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_RsaOaep_PrivateDecrypt(pEncryptedData,
                                                 (int)ulEncryptedDataLen, pData,
                                                 &decDataLen, obj, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulDataLen = decDataLen;
            break;
    #endif
#endif
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        case CKM_AES_CBC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CBC_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            decDataLen = (word32)ulEncryptedDataLen;
            if (pData == NULL) {
                *pulDataLen = decDataLen;
                return CKR_OK;
            }
            if (decDataLen > (word32)*pulDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCbc_Decrypt(pEncryptedData, (int)ulEncryptedDataLen,
                                              pData, &decDataLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulDataLen = decDataLen;
            break;
        case CKM_AES_CBC_PAD:
            if (!WP11_Session_IsOpInitialized(session,
                                                   WP11_INIT_AES_CBC_PAD_DEC)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }

            decDataLen = (word32)ulEncryptedDataLen;
            if (pData == NULL) {
                *pulDataLen = decDataLen - 1;
                return CKR_OK;
            }

            ret = WP11_AesCbcPad_Decrypt(pEncryptedData,
                                                 (int)ulEncryptedDataLen, pData,
                                                 &decDataLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulDataLen = decDataLen;
            break;
    #endif
    #ifdef HAVE_AESCTR
        case CKM_AES_CTR:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTR_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pEncryptedData == NULL) {
                *pulDataLen = ulEncryptedDataLen;
                return CKR_OK;
            }
            if (ulEncryptedDataLen > *pulDataLen)
                return CKR_BUFFER_TOO_SMALL;

            decDataLen = (word32)*pulDataLen;
            ret = WP11_AesCtr_Do(pEncryptedData,
                    (word32)ulEncryptedDataLen, pData, &decDataLen, session);
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            *pulDataLen = decDataLen;
            break;
    #endif
    #ifdef HAVE_AESGCM
        case CKM_AES_GCM:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_GCM_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            decDataLen = (word32)ulEncryptedDataLen -
                                            WP11_AesGcm_GetTagBits(session) / 8;
            if (pData == NULL) {
                *pulDataLen = decDataLen;
                return CKR_OK;
            }
            if (decDataLen > (word32)*pulDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesGcm_Decrypt(pEncryptedData, (int)ulEncryptedDataLen,
                                              pData, &decDataLen, obj, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulDataLen = decDataLen;
            break;
    #endif
    #ifdef HAVE_AESCCM
        case CKM_AES_CCM:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CCM_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            decDataLen = (word32)ulEncryptedDataLen -
                                            WP11_AesCcm_GetMacLen(session);
            if (pData == NULL) {
                *pulDataLen = decDataLen;
                return CKR_OK;
            }
            if (decDataLen > (word32)*pulDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCcm_Decrypt(pEncryptedData, (int)ulEncryptedDataLen,
                                      pData, &decDataLen, obj, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulDataLen = decDataLen;
            break;
    #endif
    #ifdef HAVE_AESECB
        case CKM_AES_ECB:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_ECB_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            decDataLen = (word32)ulEncryptedDataLen;
            if (pData == NULL) {
                *pulDataLen = decDataLen;
                return CKR_OK;
            }
            if (decDataLen > (word32)*pulDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesEcb_Decrypt(pEncryptedData, (int)ulEncryptedDataLen,
                                      pData, &decDataLen, obj, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulDataLen = decDataLen;
            break;
    #endif
    #ifdef HAVE_AESCTS
        case CKM_AES_CTS:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTS_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            decDataLen = (word32)*pulDataLen;
            if (pData == NULL) {
                *pulDataLen = ulEncryptedDataLen;
                return CKR_OK;
            }
            if (ulEncryptedDataLen > *pulDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCts_Decrypt(pEncryptedData, (int)ulEncryptedDataLen,
                                              pData, &decDataLen, session);
            if (ret == BUFFER_E)
                return CKR_BUFFER_TOO_SMALL;
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulDataLen = decDataLen;
            break;
    #endif
    #ifdef HAVE_AES_KEYWRAP
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_PAD:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_KEYWRAP_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            /* AES Key Wrap unwrapping reduces the size by 8 bytes (the
             * integrity check value). If using padding then its even smaller
             * but we can't know the final size without decrypting first. */
            decDataLen = (word32)(ulEncryptedDataLen - KEYWRAP_BLOCK_SIZE);
            if (pData == NULL) {
                *pulDataLen = decDataLen;
                return CKR_OK;
            }
            if (decDataLen > (word32)*pulDataLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesKeyWrap_Decrypt(pEncryptedData,
                    (word32)ulEncryptedDataLen, pData, &decDataLen, session);
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            if (mechanism == CKM_AES_KEY_WRAP_PAD) {
                int i;
                byte padValue = pData[decDataLen - 1];
                if (padValue > KEYWRAP_BLOCK_SIZE || padValue > decDataLen)
                    return CKR_FUNCTION_FAILED;
                for (i = 0; i < padValue; i++) {
                    if (pData[decDataLen - 1 - i] != padValue)
                        return CKR_FUNCTION_FAILED;
                }
                decDataLen -= padValue;
            }
            *pulDataLen = decDataLen;
            break;
    #endif
#endif
        default:
            (void)decDataLen;
            (void)ret;
            (void)ulEncryptedDataLen;
            (void)pData;
            return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/**
 * Continue decrypting multi-part data.
 *
 * @param  hSession            [in]      Handle of session.
 * @param  pEncryptedPart      [in]      Data to decrypt.
 * @param  ulEncryptedPartLen  [in]      Length of data in bytes.
 * @param  pPart               [in]      Buffer to hold decrypted data.
 *                                       NULL indicates length required.
 * @param  pulPartLen          [in,out]  On in, length of buffer in bytes.
 *                                       On out, length of decrypted data in
 *                                       bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pEncryptedData or pulDataLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_DecryptInit has not been
 *          successfully called.
 *          CKR_BUFFER_TOO_SMALL when the output length is too small for
 *          decrypted data.
 *          CKR_FUNCTION_FAILED when decrypting failed.
 *          CKR_MECHANISM_INVALID when wrong initialization function was used.
 *          CKR_OK on success.
 */
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                      CK_ULONG_PTR pulPartLen)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    word32 decPartLen;
    CK_MECHANISM_TYPE mechanism;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pEncryptedPart == NULL || pulPartLen == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        case CKM_AES_CBC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CBC_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            decPartLen = (word32)ulEncryptedPartLen +
                                                   WP11_AesCbc_PartLen(session);
            decPartLen &= ~0xf;
            if (pPart == NULL) {
                *pulPartLen = decPartLen;
                return CKR_OK;
            }
            if (decPartLen > (word32)*pulPartLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCbc_DecryptUpdate(pEncryptedPart,
                                                 (int)ulEncryptedPartLen, pPart,
                                                 &decPartLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulPartLen = decPartLen;
            break;
        case CKM_AES_CBC_PAD:
            if (!WP11_Session_IsOpInitialized(session,
                                                   WP11_INIT_AES_CBC_PAD_DEC)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }

            decPartLen = (word32)ulEncryptedPartLen +
                                                   WP11_AesCbc_PartLen(session);
            /* Keep last block for final. */
            if ((decPartLen & 0xf) != 0)
                decPartLen &= ~0xf;
            else if (decPartLen > 0)
                decPartLen -= 16;
            if (pPart == NULL) {
                *pulPartLen = decPartLen;
                return CKR_OK;
            }
            if (decPartLen > (word32)*pulPartLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesCbcPad_DecryptUpdate(pEncryptedPart,
                                                 (int)ulEncryptedPartLen, pPart,
                                                 &decPartLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulPartLen = decPartLen;
            break;
    #endif
    #ifdef HAVE_AESCTR
        case CKM_AES_CTR:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTR_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pPart == NULL) {
                *pulPartLen = ulEncryptedPartLen;
                return CKR_OK;
            }
            if (ulEncryptedPartLen > *pulPartLen)
                return CKR_BUFFER_TOO_SMALL;

            decPartLen = (word32)*pulPartLen;
            ret = WP11_AesCtr_Update(pEncryptedPart, (word32)ulEncryptedPartLen,
                                     pPart, &decPartLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulPartLen = decPartLen;
            break;
    #endif
    #ifdef HAVE_AESGCM
        case CKM_AES_GCM:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_GCM_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            *pulPartLen = 0;
            if (pPart == NULL)
                return CKR_OK;

            ret = WP11_AesGcm_DecryptUpdate(pEncryptedPart,
                                              (int)ulEncryptedPartLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            break;
    #endif
    #ifdef HAVE_AESCTS
        case CKM_AES_CTS:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTS_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pPart == NULL) {
                *pulPartLen = ulEncryptedPartLen + WC_AES_BLOCK_SIZE * 2;
                return CKR_OK;
            }

            decPartLen = (word32)*pulPartLen;
            ret = WP11_AesCts_DecryptUpdate(pEncryptedPart,
                    (word32)ulEncryptedPartLen, pPart, &decPartLen, session);
            if (ret == BUFFER_E)
                return CKR_BUFFER_TOO_SMALL;
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulPartLen = decPartLen;
            break;
    #endif
#endif
        default:
            (void)decPartLen;
            (void)ret;
            (void)ulEncryptedPartLen;
            (void)pPart;
            return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/**
 * Finishes decrypting multi-part data.
 *
 * @param  hSession        [in]      Handle of session.
 * @param  plastPart       [in]      Buffer to hold decrypted data.
 *                                   NULL indicates length required.
 * @param  pulLastPartLen  [in,out]  On in, length of buffer in bytes.
 *                                   On out, length of decrypted data in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pulLastPartLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_DecryptInit has not been
 *          successfully called.
 *          CKR_BUFFER_TOO_SMALL when the output length is too small for
 *          decrypted data.
 *          CKR_FUNCTION_FAILED when decrypting failed.
 *          CKR_MECHANISM_INVALID when wrong initialization function was used.
 *          CKR_OK on success.
 */
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                     CK_ULONG_PTR pulLastPartLen)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    word32 decPartLen;
    CK_MECHANISM_TYPE mechanism;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pulLastPartLen == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        case CKM_AES_CBC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CBC_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            decPartLen = WP11_AesCbc_PartLen(session);
            if (decPartLen != 0) {
                WP11_AesCbc_DecryptFinal(session);
                return CKR_DATA_LEN_RANGE;
            }
            *pulLastPartLen = 0;
            if (pLastPart == NULL)
                return CKR_OK;

            ret = WP11_AesCbc_DecryptFinal(session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            break;
        case CKM_AES_CBC_PAD:
            if (!WP11_Session_IsOpInitialized(session,
                                                   WP11_INIT_AES_CBC_PAD_DEC)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }

            decPartLen = WP11_AesCbc_PartLen(session);
            if (decPartLen != 16) {
                WP11_AesCbc_DecryptFinal(session);
                return CKR_DATA_LEN_RANGE;
            }
            *pulLastPartLen = 15;
            if (pLastPart == NULL)
                return CKR_OK;

            ret = WP11_AesCbcPad_DecryptFinal(pLastPart, &decPartLen, session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulLastPartLen = decPartLen;
            break;
    #endif
    #ifdef HAVE_AESCTR
        case CKM_AES_CTR:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTR_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pLastPart == NULL) {
                *pulLastPartLen = 0;
                return CKR_OK;
            }

            ret = WP11_AesCtr_Final(session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulLastPartLen = 0;
            break;
    #endif
    #ifdef HAVE_AESGCM
        case CKM_AES_GCM:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_GCM_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            decPartLen = WP11_AesGcm_EncDataLen(session) -
                                            WP11_AesGcm_GetTagBits(session) / 8;
            if (pLastPart == NULL) {
                *pulLastPartLen = decPartLen;
                return CKR_OK;
            }
            if (decPartLen > (word32)*pulLastPartLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_AesGcm_DecryptFinal(pLastPart, &decPartLen, obj,
                                                                       session);
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulLastPartLen = decPartLen;
            break;
    #endif
    #ifdef HAVE_AESCTS
        case CKM_AES_CTS:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CTS_DEC))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pLastPart == NULL) {
                *pulLastPartLen = WC_AES_BLOCK_SIZE * 2;
                return CKR_OK;
            }

            decPartLen = (word32)*pulLastPartLen;
            ret = WP11_AesCts_DecryptFinal(pLastPart, &decPartLen, session);
            if (ret == BUFFER_E)
                return CKR_BUFFER_TOO_SMALL;
            if (ret < 0)
                return CKR_FUNCTION_FAILED;
            *pulLastPartLen = decPartLen;
            break;
    #endif
#endif
        default:
            (void)decPartLen;
            (void)ret;
            (void)pLastPart;
            return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/**
 * Initialize digest operation.
 * No digest mechanisms are supported.
 *
 * @param  hSession    [in]  Handle of session.
 * @param  pMechanism  [in]  Type of operation to perform with parameters.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism is NULL.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 */
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanism)
{
    int ret;
    int init;
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;

    if (pMechanism->pParameter != NULL ||
        pMechanism->ulParameterLen != 0) {

        return CKR_MECHANISM_PARAM_INVALID;
    }
    init = WP11_INIT_DIGEST;
    ret = WP11_Digest_Init(pMechanism->mechanism, session);

    if (ret == 0) {
        WP11_Session_SetMechanism(session, pMechanism->mechanism);
        WP11_Session_SetOpInitialized(session, init);
    }

    return ret;
}

/**
 * Digest single-part data.
 * No digest mechanisms are supported.
 *
 * @param  hSession      [in]      Handle of session.
 * @param  pData         [in]      Data to be digested.
 * @param  ulDataLen     [in]      Length of data in bytes.
 * @param  pDigest       [in]      Buffer to hold digest output.
 *                                 NULL indicates length required.
 * @param  pulDigestLen  [in,out]  On in, length of the buffer.
 *                                 On out, length of the digest data in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pData, ulDataLen or pulDigestLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_DigestInit has not been
 *          successfully called.
 */
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                  CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
                  CK_ULONG_PTR pulDigestLen)
{
    word32 hashLen;
    int ret;
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pData == NULL || ulDataLen == 0 || pulDigestLen == NULL)
        return CKR_ARGUMENTS_BAD;

    hashLen = (word32)*pulDigestLen;
    ret = WP11_Digest_Single(pData, (word32)ulDataLen, pDigest, &hashLen,
                             session);
    *pulDigestLen = hashLen;

    return ret;
}

/**
 * Continue digesting multi-part data.
 * No digest mechanisms are supported.
 *
 * @param  hSession      [in]      Handle of session.
 * @param  pPart         [in]      Data to be digested.
 * @param  ulPartLen     [in]      Length of data in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pPart is NULL or ulPartLen is 0.
 *          CKR_OPERATION_NOT_INITIALIZED when C_DigestInit has not been
 *          successfully called.
 */
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                        CK_ULONG ulPartLen)
{
    int ret;
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pPart == NULL || ulPartLen == 0)
        return CKR_ARGUMENTS_BAD;
    if (!WP11_Session_IsOpInitialized(session, WP11_INIT_DIGEST))
        return CKR_OPERATION_NOT_INITIALIZED;

    ret = WP11_Digest_Update(pPart, (word32)ulPartLen, session);

    return ret;
}

/**
 * Continues digesting multi-part data by digesting the value in the key.
 * No digest mechanisms are supported.
 *
 * @param  hSession  [in]  Handle of session.
 * @param  hKey      [in]  Handle of a key object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_OBJECT_HANDLE_INVALID when key object handle is not valid.
 *          CKR_OPERATION_NOT_INITIALIZED when C_DigestInit has not been
 *          successfully called.
 */
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;

    ret = WP11_Object_Find(session, hKey, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    ret = WP11_Digest_Key(obj, session);

    return ret;
}

/**
 * Finished digesting multi-part data.
 * No digest mechanisms are supported.
 *
 * @param  hSession      [in]      Handle of session.
 * @param  pDigest       [in]      Buffer to hold digest output.
 *                                 NULL indicates length required.
 * @param  pulDigestLen  [in,out]  On in, length of the buffer.
 *                                 On out, length of the digest data in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pulDigestLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_DigestInit has not been
 *          successfully called.
 */
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                       CK_ULONG_PTR pulDigestLen)
{
    int ret;
    word32 hashLen;
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pulDigestLen == NULL)
        return CKR_ARGUMENTS_BAD;
    if (!WP11_Session_IsOpInitialized(session, WP11_INIT_DIGEST))
        return CKR_OPERATION_NOT_INITIALIZED;
    hashLen = (word32)*pulDigestLen;
    ret = WP11_Digest_Final(pDigest, &hashLen, session);
    *pulDigestLen = hashLen;

    return ret;
}

#ifdef WOLFSSL_HAVE_PRF
static int CKM_TLS_MAC_init(CK_KEY_TYPE type, CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey, WP11_Session* session)
{
    CK_TLS_MAC_PARAMS* params;
    byte server = 0;
    int ret;

    if (type != CKK_GENERIC_SECRET)
        return CKR_KEY_TYPE_INCONSISTENT;
    if (pMechanism->pParameter == NULL ||
                        pMechanism->ulParameterLen != sizeof(*params)) {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    params = (CK_TLS_MAC_PARAMS*)pMechanism->pParameter;
    if (params->prfHashMechanism == CKM_TLS_PRF) {
        if (params->ulMacLength != 12)
            return CKR_MECHANISM_PARAM_INVALID;
    }
    else {
        if (params->ulMacLength < 12)
            return CKR_MECHANISM_PARAM_INVALID;
    }
    if (params->ulServerOrClient == 1)
        server = 1;
    else if (params->ulServerOrClient != 2)
        return CKR_MECHANISM_PARAM_INVALID;
    ret = WP11_TLS_MAC_init(params->prfHashMechanism,
            params->ulMacLength, server, hKey, session);
    if (ret != 0)
        return CKR_FUNCTION_FAILED;
    return CKR_OK;
}
#endif

/**
 * Initialize signing operation.
 *
 * @param  hSession    [in]  Handle of session.
 * @param  pMechanism  [in]  Type of operation to perform with parameters.
 * @param  hKey        [in]  Handle to key object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when key object handle is not valid.
 *          CKR_KEY_TYPE_INCONSISTENT when the key type is not valid for the
 *          mechanism (operation).
 *          CKR_MECHANISM_PARAM_INVALID when mechanism's parameters are not
 *          valid for the operation.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 *          CKR_FUNCTION_FAILED when initializing fails.
 *          CKR_OK on success.
 */
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    CK_KEY_TYPE type;
    int init = 0;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;

    ret = WP11_Object_Find(session, hKey, &obj);
#ifdef WOLFSSL_MAXQ10XX_CRYPTO
    if ((ret != 0) && (hKey == 0) && (pMechanism->mechanism == CKM_ECDSA)) {
        if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0) {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        /* The private key is pre-provisioned so no object to set. */
        init = WP11_INIT_ECDSA_SIGN;
        WP11_Session_SetMechanism(session, pMechanism->mechanism);
        WP11_Session_SetOpInitialized(session, init);

        return CKR_OK;
    }
    else
#endif
    if (ret != 0) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    type = WP11_Object_GetType(obj);
    switch (pMechanism->mechanism) {
#ifndef NO_RSA
        case CKM_RSA_X_509:
            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            init = WP11_INIT_RSA_X_509_SIGN;
            break;
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_RSA_PKCS:
            if (init == 0)
                init = WP11_INIT_SHA224;
            FALL_THROUGH;
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_RSA_PKCS:
            if (init == 0)
                init = WP11_INIT_SHA256;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_RSA_PKCS:
            if (init == 0)
                init = WP11_INIT_SHA384;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_RSA_PKCS:
            if (init == 0)
                init = WP11_INIT_SHA512;
            FALL_THROUGH;
    #endif
        case CKM_RSA_PKCS:
            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            init |= WP11_INIT_RSA_PKCS_SIGN;
            break;
    #ifdef WC_RSA_PSS
        #ifdef WOLFSSL_SHA224
        case CKM_SHA224_RSA_PKCS_PSS:
            if (init == 0)
                init = WP11_INIT_SHA224;
            FALL_THROUGH;
        #endif
        #ifndef NO_SHA256
        case CKM_SHA256_RSA_PKCS_PSS:
            if (init == 0)
                init = WP11_INIT_SHA256;
            FALL_THROUGH;
        #endif
        #ifdef WOLFSSL_SHA384
        case CKM_SHA384_RSA_PKCS_PSS:
            if (init == 0)
                init = WP11_INIT_SHA384;
            FALL_THROUGH;
        #endif
        #ifdef WOLFSSL_SHA512
        case CKM_SHA512_RSA_PKCS_PSS:
            if (init == 0)
                init = WP11_INIT_SHA512;
            FALL_THROUGH;
        #endif
        case CKM_RSA_PKCS_PSS: {
            CK_RSA_PKCS_PSS_PARAMS* params;

            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            params = (CK_RSA_PKCS_PSS_PARAMS*)pMechanism->pParameter;
            ret = WP11_Session_SetPssParams(session, params->hashAlg,
                                                params->mgf, (int)params->sLen);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init |= WP11_INIT_RSA_PKCS_PSS_SIGN;
            break;
        }
    #endif
#endif
#ifdef HAVE_ECC
#ifndef NO_SHA
        case CKM_ECDSA_SHA1:
#endif
#ifdef WOLFSSL_SHA224
        case CKM_ECDSA_SHA224:
#endif
#ifndef NO_SHA256
        case CKM_ECDSA_SHA256:
#endif
#ifdef WOLFSSL_SHA384
        case CKM_ECDSA_SHA384:
#endif
#ifdef WOLFSSL_SHA512
        case CKM_ECDSA_SHA512:
#endif
        case CKM_ECDSA:
            if (type != CKK_EC)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            init = (int)(WP11_INIT_ECDSA_SIGN |
               ((pMechanism->mechanism - CKM_ECDSA) << WP11_INIT_DIGEST_SHIFT));
            break;
#endif
#ifndef NO_HMAC
    #ifndef NO_MD5
        case CKM_MD5_HMAC:
            if (init == 0)
                init = WP11_INIT_MD5;
            FALL_THROUGH;
    #endif
    #ifndef NO_SHA
        case CKM_SHA1_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA1;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA224;
            FALL_THROUGH;
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA256;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA384;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA512;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA3_224;
            FALL_THROUGH;
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA3_256;
            FALL_THROUGH;
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA3_384;
            FALL_THROUGH;
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA3_512;
    #endif
    #endif
            if (type != CKK_GENERIC_SECRET)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            ret = WP11_Hmac_Init(pMechanism->mechanism, obj, session);
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init |= WP11_INIT_HMAC_SIGN;
            break;
#endif
#ifndef NO_AES
#ifdef HAVE_AESCMAC
        case CKM_AES_CMAC_GENERAL:
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL ||
                  pMechanism->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            ret = WP11_Aes_Cmac_Init(obj, session,
                     (word32)*((CK_MAC_GENERAL_PARAMS*)pMechanism->pParameter));
            if (ret == BAD_FUNC_ARG)
                return CKR_MECHANISM_PARAM_INVALID;
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init = WP11_INIT_AES_CMAC_SIGN;
            break;
        case CKM_AES_CMAC:
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            ret = WP11_Aes_Cmac_Init(obj, session, WC_AES_BLOCK_SIZE/2);
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init = WP11_INIT_AES_CMAC_SIGN;
            break;
#endif
#endif
#ifdef WOLFSSL_HAVE_PRF
        case CKM_TLS_MAC:
            ret = CKM_TLS_MAC_init(type, pMechanism, hKey, session);
            if (ret != CKR_OK)
                return ret;
            init = WP11_INIT_TLS_MAC_SIGN;
            break;
#endif
        default:
            (void)type;
            return CKR_MECHANISM_INVALID;
    }

    WP11_Session_SetMechanism(session, pMechanism->mechanism);
    WP11_Session_SetObject(session, obj);
    WP11_Session_SetOpInitialized(session, init);

    return CKR_OK;
}

/**
 * Sign the single-part data.
 *
 * @param  hSession         [in]      Handle of session.
 * @param  pData            [in]      Data to sign.
 * @param  ulDataLen        [in]      Length of data in bytes.
 * @param  pSignature       [in]      Buffer to hold signature.
 *                                    NULL indicates length required.
 * @param  pulSignatureLen  [in,out]  On in, length of buffer in bytes.
 *                                    On out, length of signature in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pData or pulSignatureLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_SignInit has not been
 *          successfully called.
 *          CKR_BUFFER_TOO_SMALL when the output length is too small for
 *          signature data.
 *          CKR_FUNCTION_FAILED when signing fails.
 *          CKR_MECHANISM_INVALID when wrong initialization function was used.
 *          CKR_OK on success.
 */
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
             CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
             CK_ULONG_PTR pulSignatureLen)
{
    int ret = 0;
#ifndef NO_RSA
    int oid;
#endif
    WP11_Session* session;
    WP11_Object* obj = NULL;
    word32 sigLen;
    CK_MECHANISM_TYPE mechanism;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pData == NULL || pulSignatureLen == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_RSA
    #ifdef WC_RSA_DIRECT
        case CKM_RSA_X_509:
            if (!WP11_Session_IsOpInitialized(session,
                                                    WP11_INIT_RSA_X_509_SIGN)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }

            sigLen = WP11_Rsa_KeyLen(obj);
            if (pSignature == NULL) {
                *pulSignatureLen = sigLen;
                return CKR_OK;
            }
            if (sigLen > (word32)*pulSignatureLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_Rsa_Sign(pData, (int)ulDataLen, pSignature, &sigLen, obj,
                                                 WP11_Session_GetSlot(session));
            *pulSignatureLen = sigLen;
            break;
    #endif
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_RSA_PKCS:
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_RSA_PKCS:
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_RSA_PKCS:
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_RSA_PKCS:
    #endif
        case CKM_RSA_PKCS: {
            byte digest[MAX_DER_DIGEST_SZ];
            byte* data = pData;
            int dataSz = (int)ulDataLen;
            enum wc_HashType hash_type = WP11_Session_ToHashType(session);

            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_RSA_PKCS_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;
            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            sigLen = WP11_Rsa_KeyLen(obj);
            if (pSignature == NULL) {
                *pulSignatureLen = sigLen;
                return CKR_OK;
            }
            if (sigLen > (word32)*pulSignatureLen)
                return CKR_BUFFER_TOO_SMALL;

            if (hash_type != WC_HASH_TYPE_NONE) {
                if (wc_Hash(hash_type, pData, (word32)ulDataLen,
                            digest, sizeof(digest)) != 0 ||
                        (dataSz = wc_HashGetDigestSize(hash_type)) < 0) {
                    return CKR_FUNCTION_FAILED;
                }
                oid = wc_HashGetOID(hash_type);
                if (oid < 0)
                    return CKR_FUNCTION_FAILED;

                ret = wc_EncodeSignature(digest, digest, dataSz, oid);

                if (ret > 0) {
                    data = digest;
                    dataSz = ret;
                }
                else {
                    return CKR_FUNCTION_FAILED;
                }
            }

            ret = WP11_RsaPkcs15_Sign(data, (word32)dataSz, pSignature,
                                                &sigLen, obj,
                                                WP11_Session_GetSlot(session));

            *pulSignatureLen = sigLen;
            break;
        }
    #ifdef WC_RSA_PSS
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
        case CKM_RSA_PKCS_PSS: {
            byte digest[WC_MAX_DIGEST_SIZE];
            byte* data = pData;
            int dataSz = (int)ulDataLen;
            enum wc_HashType hash_type = WP11_Session_ToHashType(session);

            if (!WP11_Session_IsOpInitialized(session,
                                                 WP11_INIT_RSA_PKCS_PSS_SIGN)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }
            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            sigLen = WP11_Rsa_KeyLen(obj);
            if (pSignature == NULL) {
                *pulSignatureLen = sigLen;
                return CKR_OK;
            }
            if (sigLen > (word32)*pulSignatureLen)
                return CKR_BUFFER_TOO_SMALL;

            if (hash_type != WC_HASH_TYPE_NONE) {
                if (wc_Hash(hash_type, pData, (word32)ulDataLen,
                        digest, sizeof(digest)) != 0 ||
                        (dataSz = wc_HashGetDigestSize(hash_type)) < 0) {
                    return CKR_FUNCTION_FAILED;
                }
                data = digest;
            }

            ret = WP11_RsaPKCSPSS_Sign(data, (word32)dataSz, pSignature,
                                                         &sigLen, obj, session);
            *pulSignatureLen = sigLen;
            break;
        }
    #endif
#endif
#ifdef HAVE_ECC
#ifndef NO_SHA
        case CKM_ECDSA_SHA1:
#endif
#ifdef WOLFSSL_SHA224
        case CKM_ECDSA_SHA224:
#endif
#ifndef NO_SHA256
        case CKM_ECDSA_SHA256:
#endif
#ifdef WOLFSSL_SHA384
        case CKM_ECDSA_SHA384:
#endif
#ifdef WOLFSSL_SHA512
        case CKM_ECDSA_SHA512:
#endif
        case CKM_ECDSA: {
            byte digest[WC_MAX_DIGEST_SIZE];
            byte* data = pData;
            int dataSz = (int)ulDataLen;
            enum wc_HashType hash_type = WP11_Session_ToHashType(session);

            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_ECDSA_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;
            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            sigLen = WP11_Ec_SigLen(obj);
            if (pSignature == NULL) {
                *pulSignatureLen = sigLen;
                return CKR_OK;
            }
            if (sigLen > (word32)*pulSignatureLen)
                return CKR_BUFFER_TOO_SMALL;

            if (hash_type != WC_HASH_TYPE_NONE) {
                if (wc_Hash(hash_type, pData, (word32)ulDataLen, digest,
                        sizeof(digest)) != 0 ||
                        (dataSz = wc_HashGetDigestSize(hash_type)) < 0) {
                    return CKR_FUNCTION_FAILED;
                }
                data = digest;
            }

            ret = WP11_Ec_Sign(data, (word32)dataSz, pSignature, &sigLen, obj,
                                                 WP11_Session_GetSlot(session));
            *pulSignatureLen = sigLen;
            break;
        }
#endif
#ifndef NO_HMAC
    #ifndef NO_MD5
        case CKM_MD5_HMAC:
    #endif
    #ifndef NO_SHA
        case CKM_SHA1_HMAC:
    #endif
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_HMAC:
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_HMAC:
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_HMAC:
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_HMAC:
    #endif
    #ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512_HMAC:
    #endif
    #endif
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_HMAC_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            sigLen = WP11_Hmac_SigLen(session);
            if (pSignature == NULL) {
                *pulSignatureLen = sigLen;
                return CKR_OK;
            }
            if (sigLen > (word32)*pulSignatureLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_Hmac_Sign(pData, (int)ulDataLen, pSignature, &sigLen,
                                                                       session);
            *pulSignatureLen = sigLen;
            break;
#endif
#ifndef NO_AES
#ifdef HAVE_AESCMAC
        case CKM_AES_CMAC_GENERAL:
        case CKM_AES_CMAC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CMAC_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Aes_Cmac_Check_Len(pSignature, pulSignatureLen, session);
            if (ret != CKR_OK || pSignature == NULL)
                return ret;

            sigLen = *pulSignatureLen;
            ret = WP11_Aes_Cmac_Sign(pData, (word32)ulDataLen, pSignature,
                    &sigLen, session);
            *pulSignatureLen = sigLen;
            break;
#endif
#endif
#ifdef WOLFSSL_HAVE_PRF
        case CKM_TLS_MAC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_TLS_MAC_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (pSignature == NULL) {
                *pulSignatureLen = (CK_ULONG)WP11_TLS_MAC_get_len(session);
                return CKR_OK;
            }
            if (WP11_TLS_MAC_get_len(session) > (word32)*pulSignatureLen)
                return CKR_BUFFER_TOO_SMALL;

            sigLen = (word32)*pulSignatureLen;
            ret = WP11_TLS_MAC_sign(pData, (word32)ulDataLen, pSignature,
                    &sigLen, session);
            *pulSignatureLen = sigLen;
            break;
#endif
        default:
            (void)sigLen;
            (void)ulDataLen;
            (void)pSignature;
            return CKR_MECHANISM_INVALID;
    }
    if (ret < 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}

/**
 * Continue signing the multi-part data.
 *
 * @param  hSession   [in]  Handle of session.
 * @param  pPart      [in]  Data to sign.
 * @param  ulPartLen  [in]  Length of data in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pData is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_SignInit has not been
 *          successfully called.
 *          CKR_FUNCTION_FAILED when signing fails.
 *          CKR_MECHANISM_INVALID when wrong initialization function was used.
 *          CKR_OK on success.
 */
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                   CK_ULONG ulPartLen)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    CK_MECHANISM_TYPE mechanism;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pPart == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_HMAC
    #ifndef NO_MD5
        case CKM_MD5_HMAC:
    #endif
    #ifndef NO_SHA
        case CKM_SHA1_HMAC:
    #endif
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_HMAC:
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_HMAC:
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_HMAC:
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_HMAC:
    #endif
    #ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512_HMAC:
    #endif
    #endif
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_HMAC_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Hmac_Update(pPart, (int)ulPartLen, session);
            break;
#endif
#ifndef NO_AES
#ifdef HAVE_AESCMAC
        case CKM_AES_CMAC_GENERAL:
        case CKM_AES_CMAC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CMAC_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Aes_Cmac_Sign_Update(pPart, (word32)ulPartLen, session);
            break;
#endif
#endif
#ifdef WOLFSSL_HAVE_PRF
        case CKM_TLS_MAC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_TLS_MAC_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Session_UpdateData(session, pPart, (word32)ulPartLen);
            break;
#endif
        default:
            (void)ulPartLen;
            return CKR_MECHANISM_INVALID;
    }
    if (ret < 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}

/**
 * Finish signing the multi-part data.
 *
 * @param  hSession         [in]      Handle of session.
 * @param  pSignature       [in]      Buffer to hold signature.
 *                                    NULL indicates length required.
 * @param  pulSignatureLen  [in,out]  On in, length of buffer in bytes.
 *                                    On out, length of signature in
 *                                    bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pData or pulSignatureLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_SignInit has not been
 *          successfully called.
 *          CKR_BUFFER_TOO_SMALL when the output length is too small for
 *          signature data.
 *          CKR_FUNCTION_FAILED when signing fails.
 *          CKR_MECHANISM_INVALID when wrong initialization function was used.
 *          CKR_OK on success.
 */
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                  CK_ULONG_PTR pulSignatureLen)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    CK_MECHANISM_TYPE mechanism;
    word32 sigLen;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pulSignatureLen == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_HMAC
    #ifndef NO_MD5
        case CKM_MD5_HMAC:
    #endif
    #ifndef NO_SHA
        case CKM_SHA1_HMAC:
    #endif
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_HMAC:
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_HMAC:
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_HMAC:
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_HMAC:
    #endif
    #ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512_HMAC:
    #endif
    #endif
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_HMAC_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            sigLen = WP11_Hmac_SigLen(session);
            if (pSignature == NULL) {
                *pulSignatureLen = sigLen;
                return CKR_OK;
            }
            if (sigLen > (word32)*pulSignatureLen)
                return CKR_BUFFER_TOO_SMALL;

            ret = WP11_Hmac_SignFinal(pSignature, &sigLen, session);
            *pulSignatureLen = sigLen;
            break;
#endif
#ifndef NO_AES
#ifdef HAVE_AESCMAC
        case CKM_AES_CMAC_GENERAL:
        case CKM_AES_CMAC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CMAC_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Aes_Cmac_Check_Len(pSignature, pulSignatureLen, session);
            if (ret != CKR_OK || pSignature == NULL)
                return ret;

            sigLen = *pulSignatureLen;
            ret = WP11_Aes_Cmac_Sign_Final(pSignature, &sigLen, session);
            *pulSignatureLen = sigLen;
            break;
#endif
#endif
#ifdef WOLFSSL_HAVE_PRF
        case CKM_TLS_MAC: {
            byte* data = NULL;
            word32 dataLen = 0;

            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_TLS_MAC_SIGN))
                return CKR_OPERATION_NOT_INITIALIZED;

            WP11_Session_GetData(session, &data, &dataLen);
            ret = (int)C_Sign(hSession, data, dataLen, pSignature,
                pulSignatureLen);
            WP11_Session_FreeData(session);
            if (ret != CKR_OK)
                return ret;

            break;
        }
#endif
        default:
            (void)sigLen;
            (void)pSignature;
            return CKR_MECHANISM_INVALID;
    }
    if (ret < 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}

/**
 * Initialize signing operation that recovers data from signature.
 * No mechanisms are supported.
 *
 * @param  hSession    [in]  Handle of session.
 * @param  pMechanism  [in]  Type of operation to perform with parameters.
 * @param  hKey        [in]  Handle to key object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when key object handle is not valid.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 */
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;

    ret = WP11_Object_Find(session, hKey, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    return CKR_MECHANISM_INVALID;
}

/**
 * Sign the data such that the data can be recovered from the signature.
 *
 * @param  hSession         [in]      Handle of session.
 * @param  pData            [in]      Data to sign.
 * @param  ulDataLen        [in]      Length of data in bytes.
 * @param  pSignature       [in]      Buffer to hold signature.
 *                                    NULL indicates length required.
 * @param  pulSignatureLen  [in,out]  On in, length of buffer in bytes.
 *                                    On out, length of signature in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pData or pulSignatureLen is NULL, or
 *          ulDataLen is 0.
 *          CKR_OPERATION_NOT_INITIALIZED when C_SignRecoverInit has not been
 *          successfully called.
 */
CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                    CK_ULONG_PTR pulSignatureLen)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pData == NULL || ulDataLen == 0 || pulSignatureLen == NULL)
        return CKR_ARGUMENTS_BAD;

    (void)pSignature;

    return CKR_OPERATION_NOT_INITIALIZED;
}

/**
 * Initialize verification operation.
 *
 * @param  hSession    [in]  Handle of session.
 * @param  pMechanism  [in]  Type of operation to perform with parameters.
 * @param  hKey        [in]  Handle to key object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when key object handle is not valid.
 *          CKR_KEY_TYPE_INCONSISTENT when the key type is not valid for the
 *          mechanism (operation).
 *          CKR_MECHANISM_PARAM_INVALID when mechanism's parameters are not
 *          valid for the operation.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 *          CKR_FUNCTION_FAILED when initializing fails.
 *          CKR_OK on success.
 */
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    CK_KEY_TYPE type;
    int init = 0;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;

    ret = WP11_Object_Find(session, hKey, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    type = WP11_Object_GetType(obj);
    switch (pMechanism->mechanism) {
#ifndef NO_RSA
        case CKM_RSA_X_509:
            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            init = WP11_INIT_RSA_X_509_VERIFY;
            break;
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_RSA_PKCS:
            if (init == 0)
                init = WP11_INIT_SHA224;
            FALL_THROUGH;
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_RSA_PKCS:
            if (init == 0)
                init = WP11_INIT_SHA256;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_RSA_PKCS:
            if (init == 0)
                init = WP11_INIT_SHA384;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_RSA_PKCS:
            if (init == 0)
                init = WP11_INIT_SHA512;
            FALL_THROUGH;
    #endif
        case CKM_RSA_PKCS:
            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            init |= WP11_INIT_RSA_PKCS_VERIFY;
            break;
    #ifdef WC_RSA_PSS
        #ifdef WOLFSSL_SHA224
        case CKM_SHA224_RSA_PKCS_PSS:
            if (init == 0)
                init = WP11_INIT_SHA224;
            FALL_THROUGH;
        #endif
        #ifndef NO_SHA256
        case CKM_SHA256_RSA_PKCS_PSS:
            if (init == 0)
                init = WP11_INIT_SHA256;
            FALL_THROUGH;
        #endif
        #ifdef WOLFSSL_SHA384
        case CKM_SHA384_RSA_PKCS_PSS:
            if (init == 0)
                init = WP11_INIT_SHA384;
            FALL_THROUGH;
        #endif
        #ifdef WOLFSSL_SHA512
        case CKM_SHA512_RSA_PKCS_PSS:
            if (init == 0)
                init = WP11_INIT_SHA512;
            FALL_THROUGH;
        #endif
        case CKM_RSA_PKCS_PSS: {
            CK_RSA_PKCS_PSS_PARAMS* params;

            if (type != CKK_RSA)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;

            params = (CK_RSA_PKCS_PSS_PARAMS*)pMechanism->pParameter;
            ret = WP11_Session_SetPssParams(session, params->hashAlg,
                                                params->mgf, (int)params->sLen);
            if (ret != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            init |= WP11_INIT_RSA_PKCS_PSS_VERIFY;
            break;
        }
    #endif
#endif
#ifdef HAVE_ECC
#ifndef NO_SHA
        case CKM_ECDSA_SHA1:
#endif
#ifdef WOLFSSL_SHA224
        case CKM_ECDSA_SHA224:
#endif
#ifndef NO_SHA256
        case CKM_ECDSA_SHA256:
#endif
#ifdef WOLFSSL_SHA384
        case CKM_ECDSA_SHA384:
#endif
#ifdef WOLFSSL_SHA512
        case CKM_ECDSA_SHA512:
#endif
        case CKM_ECDSA:
            if (type != CKK_EC)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            init = (int)(WP11_INIT_ECDSA_VERIFY |
               ((pMechanism->mechanism - CKM_ECDSA) << WP11_INIT_DIGEST_SHIFT));
            break;
#endif
#ifndef NO_HMAC
    #ifndef NO_MD5
        case CKM_MD5_HMAC:
            if (init == 0)
                init = WP11_INIT_MD5;
            FALL_THROUGH;
    #endif
    #ifndef NO_SHA
        case CKM_SHA1_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA1;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA224;
            FALL_THROUGH;
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA256;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA384;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA512;
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA3_224;
            FALL_THROUGH;
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA3_256;
            FALL_THROUGH;
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA3_384;
            FALL_THROUGH;
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512_HMAC:
            if (init == 0)
                init = WP11_INIT_SHA3_512;
    #endif
    #endif
            if (type != CKK_GENERIC_SECRET)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            ret = WP11_Hmac_Init(pMechanism->mechanism, obj, session);
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init |= WP11_INIT_HMAC_VERIFY;
            break;
#endif
#ifndef NO_AES
#ifdef HAVE_AESCMAC
        case CKM_AES_CMAC_GENERAL:
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter == NULL ||
                  pMechanism->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            ret = WP11_Aes_Cmac_Init(obj, session,
                     (word32)*((CK_MAC_GENERAL_PARAMS*)pMechanism->pParameter));
            if (ret == BAD_FUNC_ARG)
                return CKR_MECHANISM_PARAM_INVALID;
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init = WP11_INIT_AES_CMAC_VERIFY;
            break;
        case CKM_AES_CMAC:
            if (type != CKK_AES)
                return CKR_KEY_TYPE_INCONSISTENT;
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            ret = WP11_Aes_Cmac_Init(obj, session, WC_AES_BLOCK_SIZE/2);
            if (ret != 0)
                return CKR_FUNCTION_FAILED;
            init = WP11_INIT_AES_CMAC_VERIFY;
            break;
#endif
#endif
#ifdef WOLFSSL_HAVE_PRF
        case CKM_TLS_MAC:
            ret = CKM_TLS_MAC_init(type, pMechanism, hKey, session);
            if (ret != CKR_OK)
                return ret;
            init = WP11_INIT_TLS_MAC_VERIFY;
            break;
#endif
        default:
            (void)type;
            return CKR_MECHANISM_INVALID;
    }

    WP11_Session_SetMechanism(session, pMechanism->mechanism);
    WP11_Session_SetObject(session, obj);
    WP11_Session_SetOpInitialized(session, init);

    return CKR_OK;
}

/**
 * Verify the single-part data.
 *
 * @param  hSession        [in]  Handle of session.
 * @param  pData           [in]  Data to verify.
 * @param  ulDataLen       [in]  Length of data in bytes.
 * @param  pSignature      [in]  Signature data.
 * @param  ulSignatureLen  [in]  Length of signature in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pData or pSignature is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_VerifyInit has not been
 *          successfully called.
 *          CKR_FUNCTION_FAILED when verification fails.
 *          CKR_MECHANISM_INVALID when wrong initialization function was used.
 *          CKR_SIGNATURE_INVALID when the signature does not verify the data.
 *          CKR_OK on success.
 */
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
               CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
               CK_ULONG ulSignatureLen)
{
    int ret = 0;
    int stat = 0;
#ifndef NO_RSA
    int oid = 0;
#endif
    WP11_Session* session = NULL;
    WP11_Object* obj = NULL;
    CK_MECHANISM_TYPE mechanism = 0;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pData == NULL || pSignature == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_RSA
    #ifdef WC_RSA_DIRECT
        case CKM_RSA_X_509:
            if (!WP11_Session_IsOpInitialized(session,
                                                  WP11_INIT_RSA_X_509_VERIFY)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }

            ret = WP11_Rsa_Verify(pSignature, (int)ulSignatureLen, pData,
                                                    (int)ulDataLen, &stat, obj);
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
        case CKM_RSA_PKCS: {
            byte digest[MAX_DER_DIGEST_SZ];
            byte* data = pData;
            int dataSz = (int)ulDataLen;
            enum wc_HashType hash_type = WP11_Session_ToHashType(session);

            if (!WP11_Session_IsOpInitialized(session,
                                                   WP11_INIT_RSA_PKCS_VERIFY)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }
            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (hash_type != WC_HASH_TYPE_NONE) {
                if (wc_Hash(hash_type, pData, (word32)ulDataLen, digest,
                        sizeof(digest)) != 0 ||
                        (dataSz = wc_HashGetDigestSize(hash_type)) < 0) {
                    return CKR_FUNCTION_FAILED;
                }
                oid = wc_HashGetOID(hash_type);
                if (oid < 0)
                    return CKR_FUNCTION_FAILED;

                ret = wc_EncodeSignature(digest, digest, dataSz, oid);

                if (ret > 0) {
                    data = digest;
                    dataSz = ret;
                }
                else {
                    return CKR_FUNCTION_FAILED;
                }
            }

            ret = WP11_RsaPkcs15_Verify(pSignature, (int)ulSignatureLen, data,
                (word32)dataSz, &stat, obj);
            break;
        }
    #ifdef WC_RSA_PSS
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
        case CKM_RSA_PKCS_PSS: {
            byte digest[WC_MAX_DIGEST_SIZE];
            byte* data = pData;
            int dataSz = (int)ulDataLen;
            enum wc_HashType hash_type = WP11_Session_ToHashType(session);

            if (!WP11_Session_IsOpInitialized(session,
                                               WP11_INIT_RSA_PKCS_PSS_VERIFY)) {
                return CKR_OPERATION_NOT_INITIALIZED;
            }
            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (hash_type != WC_HASH_TYPE_NONE) {
                if (wc_Hash(hash_type, pData, (word32)ulDataLen, digest,
                        sizeof(digest)) != 0 ||
                        (dataSz = wc_HashGetDigestSize(hash_type)) < 0) {
                    return CKR_FUNCTION_FAILED;
                }
                data = digest;
            }

            ret = WP11_RsaPKCSPSS_Verify(pSignature, (int)ulSignatureLen, data,
                                           (word32)dataSz, &stat, obj, session);
            break;
        }
    #endif
#endif
#ifdef HAVE_ECC
#ifndef NO_SHA
        case CKM_ECDSA_SHA1:
#endif
#ifdef WOLFSSL_SHA224
        case CKM_ECDSA_SHA224:
#endif
#ifndef NO_SHA256
        case CKM_ECDSA_SHA256:
#endif
#ifdef WOLFSSL_SHA384
        case CKM_ECDSA_SHA384:
#endif
#ifdef WOLFSSL_SHA512
        case CKM_ECDSA_SHA512:
#endif
        case CKM_ECDSA: {
            byte digest[WC_MAX_DIGEST_SIZE];
            byte* data = pData;
            int dataSz = (int)ulDataLen;
            enum wc_HashType hash_type = WP11_Session_ToHashType(session);

            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_ECDSA_VERIFY))
                return CKR_OPERATION_NOT_INITIALIZED;
            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (hash_type != WC_HASH_TYPE_NONE) {
                if (wc_Hash(hash_type, pData, (word32)ulDataLen, digest,
                        sizeof(digest)) != 0 ||
                        (dataSz = wc_HashGetDigestSize(hash_type)) < 0) {
                    return CKR_FUNCTION_FAILED;
                }
                data = digest;
            }

            ret = WP11_Ec_Verify(pSignature, (int)ulSignatureLen, data,
                                 (word32)dataSz, &stat, obj);
            break;
        }
#endif
#ifndef NO_HMAC
    #ifndef NO_MD5
        case CKM_MD5_HMAC:
    #endif
    #ifndef NO_SHA
        case CKM_SHA1_HMAC:
    #endif
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_HMAC:
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_HMAC:
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_HMAC:
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_HMAC:
    #endif
    #ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512_HMAC:
    #endif
    #endif
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_HMAC_VERIFY))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Hmac_Verify(pSignature, (int)ulSignatureLen, pData,
                                                (int)ulDataLen, &stat, session);
            break;
#endif
#ifndef NO_AES
#ifdef HAVE_AESCMAC
        case CKM_AES_CMAC_GENERAL:
        case CKM_AES_CMAC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CMAC_VERIFY))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Aes_Cmac_Verify(pData, (word32)ulDataLen, pSignature,
                    (word32)ulSignatureLen, &stat, session);
            break;
#endif
#endif
#ifdef WOLFSSL_HAVE_PRF
        case CKM_TLS_MAC: {
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_TLS_MAC_VERIFY))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_TLS_MAC_verify(pData, (word32)ulDataLen, pSignature,
                    (word32)ulSignatureLen, &stat, session);
            break;
        }
#endif
        default:
            (void)ulDataLen;
            (void)ulSignatureLen;
            return CKR_MECHANISM_INVALID;
    }
    if (ret < 0)
        return CKR_FUNCTION_FAILED;
    if (!stat)
        return CKR_SIGNATURE_INVALID;

    return CKR_OK;
}

/**
 * Continue verifying the multi-part data.
 *
 * @param  hSession   [in]  Handle of session.
 * @param  pPart      [in]  Data to verify.
 * @param  ulPartLen  [in]  Length of data in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pPart is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_VerifyInit has not been
 *          successfully called.
 *          CKR_FUNCTION_FAILED when verification fails.
 *          CKR_MECHANISM_INVALID when wrong initialization function was used.
 *          CKR_OK on success.
 */
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen)
{
    int ret;
    WP11_Session* session;
    WP11_Object* obj = NULL;
    CK_MECHANISM_TYPE mechanism;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pPart == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_HMAC
    #ifndef NO_MD5
        case CKM_MD5_HMAC:
    #endif
    #ifndef NO_SHA
        case CKM_SHA1_HMAC:
    #endif
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_HMAC:
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_HMAC:
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_HMAC:
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_HMAC:
    #endif
    #ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512_HMAC:
    #endif
    #endif
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_HMAC_VERIFY))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Hmac_Update(pPart, (int)ulPartLen, session);
            break;
#endif
#ifndef NO_AES
#ifdef HAVE_AESCMAC
        case CKM_AES_CMAC_GENERAL:
        case CKM_AES_CMAC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CMAC_VERIFY))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Aes_Cmac_Sign_Update(pPart, (word32)ulPartLen, session);
            break;
#endif
#endif
        default:
            (void)ulPartLen;
            return CKR_MECHANISM_INVALID;
    }
    if (ret < 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}

/**
 * Finishes verifying the multi-part data.
 *
 * @param  hSession        [in]  Handle of session.
 * @param  pSignature      [in]  Signature data.
 * @param  ulSignatureLen  [in]  Length of signature in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pSignature is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_VerifyInit has not been
 *          successfully called.
 *          CKR_FUNCTION_FAILED when verification fails.
 *          CKR_MECHANISM_INVALID when wrong initialization function was used.
 *          CKR_SIGNATURE_INVALID when the signature does not verify the data.
 *          CKR_OK on success.
 */
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    int ret = 0;
    int stat = 0;
    WP11_Session* session = NULL;
    WP11_Object* obj = NULL;
    CK_MECHANISM_TYPE mechanism = 0;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pSignature == NULL)
        return CKR_ARGUMENTS_BAD;

    WP11_Session_GetObject(session, &obj);
    if (obj == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    mechanism = WP11_Session_GetMechanism(session);
    switch (mechanism) {
#ifndef NO_HMAC
    #ifndef NO_MD5
        case CKM_MD5_HMAC:
    #endif
    #ifndef NO_SHA
        case CKM_SHA1_HMAC:
    #endif
    #ifdef WOLFSSL_SHA224
        case CKM_SHA224_HMAC:
    #endif
    #ifndef NO_SHA256
        case CKM_SHA256_HMAC:
    #endif
    #ifdef WOLFSSL_SHA384
        case CKM_SHA384_HMAC:
    #endif
    #ifdef WOLFSSL_SHA512
        case CKM_SHA512_HMAC:
    #endif
    #ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384_HMAC:
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512_HMAC:
    #endif
    #endif
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_HMAC_VERIFY))
                return CKR_OPERATION_NOT_INITIALIZED;

            if (!WP11_Session_IsHashOpInitialized(session, (int)mechanism))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Hmac_VerifyFinal(pSignature, (int)ulSignatureLen, &stat,
                                                                       session);
            break;
#endif
#ifndef NO_AES
#ifdef HAVE_AESCMAC
        case CKM_AES_CMAC_GENERAL:
        case CKM_AES_CMAC:
            if (!WP11_Session_IsOpInitialized(session, WP11_INIT_AES_CMAC_VERIFY))
                return CKR_OPERATION_NOT_INITIALIZED;

            ret = WP11_Aes_Cmac_Verify_Final(pSignature, (word32)ulSignatureLen,
                    &stat, session);
            break;
#endif
#endif
        default:
            (void)ulSignatureLen;
            return CKR_MECHANISM_INVALID;
    }
    if (ret < 0)
        return CKR_FUNCTION_FAILED;
    if (!stat)
        return CKR_SIGNATURE_INVALID;

    return CKR_OK;
}

/**
 * Initialize verification operation where data is recovered from the signature.
 *
 * @param  hSession    [in]  Handle of session.
 * @param  pMechanism  [in]  Type of operation to perform with parameters.
 * @param  hKey        [in]  Handle to key object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when key object handle is not valid.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 */
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_OBJECT_HANDLE hKey)
{
    int ret;
    int init = 0;
    WP11_Session* session;
    WP11_Object* obj;
    CK_BBOOL getVar;
    CK_ULONG getVarLen = sizeof(CK_BBOOL);

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;
    if (hKey == 0)
        return CKR_OBJECT_HANDLE_INVALID;

    switch(pMechanism->mechanism) {
        case CKM_RSA_PKCS:
            init = WP11_INIT_RSA_PKCS_VERIFY_RECOVER;
            break;
        case CKM_RSA_X_509:
            init = WP11_INIT_RSA_X_509_VERIFY_RECOVER;
            break;
        default:
            return CKR_MECHANISM_INVALID;
    }

    if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    ret = WP11_Object_Find(session, hKey, &obj);
    if (ret != CKR_OK)
        return ret;

    if (WP11_Object_GetClass(obj) != CKO_PUBLIC_KEY) {
        return CKR_KEY_HANDLE_INVALID;
    }

    if (WP11_Object_GetType(obj) != CKK_RSA) {
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    ret = WP11_Object_GetAttr(obj, CKA_VERIFY, &getVar, &getVarLen);
    if (ret != CKR_OK)
        return CKR_FUNCTION_FAILED;

    if (getVar != CK_TRUE)
        return CKR_KEY_FUNCTION_NOT_PERMITTED;

    WP11_Session_SetMechanism(session, pMechanism->mechanism);
    WP11_Session_SetObject(session, obj);
    WP11_Session_SetOpInitialized(session, init);


    return CKR_OK;
}

/**
 * Verify the signature where the data is recovered from the signature.
 *
 * @param  hSession        [in]      Handle of session.
 * @param  pSignature      [in]      Signature data.
 * @param  ulSignatureLen  [in]      Length of signature in bytes.
 * @param  pData           [in]      Buffer to hold data that was verified.
 * @param  ulDataLen       [in,out]  On in, length of buffer in bytes.
 *                                   On out, length of data in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pSignature or pulDataLen is NULL, or
 *          ulSignatureLen is 0.
 *          CKR_OPERATION_NOT_INITIALIZED when C_VerifyInit has not been
 *          successfully called.
 *          CKR_OK on success.
 */
CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
                      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    WP11_Session* session;
#ifndef NO_RSA
    int ret;
    WP11_Object* obj = NULL;
    word32 decDataLen;
    CK_MECHANISM_TYPE mechanism;
#endif

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pSignature == NULL || ulSignatureLen == 0 || pulDataLen == NULL)
        return CKR_ARGUMENTS_BAD;

#ifdef NO_RSA
    (void) pData;
    return CKR_MECHANISM_INVALID;
#else

    mechanism = WP11_Session_GetMechanism(session);
    WP11_Session_GetObject(session, &obj);

    if (obj == NULL) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    decDataLen = WP11_Rsa_KeyLen(obj);
    if (pData == NULL) {
        *pulDataLen = decDataLen;
        return CKR_OK;
    }
    if (decDataLen > (word32)*pulDataLen)
        return CKR_BUFFER_TOO_SMALL;

    switch (mechanism) {
        case CKM_RSA_PKCS:
            if (!WP11_Session_IsOpInitialized(session,
                WP11_INIT_RSA_PKCS_VERIFY_RECOVER))
                return CKR_OPERATION_NOT_INITIALIZED;
            break;
        case CKM_RSA_X_509:
            if (!WP11_Session_IsOpInitialized(session,
                WP11_INIT_RSA_X_509_VERIFY_RECOVER))
                return CKR_OPERATION_NOT_INITIALIZED;
            break;
        default:
            return CKR_MECHANISM_INVALID;
    }

    ret = WP11_Rsa_Verify_Recover(mechanism, pSignature, (word32)ulSignatureLen,
                                  pData, pulDataLen, obj);

    if (ret != CKR_OK) {
        return ret;
    }

    return CKR_OK;
#endif
}

/**
 * Continue digesting and encrypting multi-part data.
 *
 * @param  hSession             [in]      Handle of session.
 * @param  pPart                [in]      Data to digest and encrypt.
 * @param  ulPartLen            [in]      Length of data in bytes.
 * @param  pEncryptedPart       [in]      Buffer to hold encrypted data.
 *                                        NULL indicates length required.
 * @param  pulEncryptedPartLen  [in,out]  On in, length of buffer in bytes.
 *                                        On out, length of encrypted data in
 *                                        bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pPart or pulEncryptedPartLen is NULL or
 *          ulPartLen is 0.
 *          CKR_OPERATION_NOT_INITIALIZED when C_EncryptInit and C_DigestInit
 *          have not been successfully called.
 */
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG_PTR pulEncryptedPartLen)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pPart == NULL || ulPartLen == 0 || pulEncryptedPartLen == NULL)
        return CKR_ARGUMENTS_BAD;

    (void)pEncryptedPart;

    return CKR_OPERATION_NOT_INITIALIZED;
}

/**
 * Continue decrypting and digesting multi-part data.
 *
 * @param  hSession            [in]      Handle of session.
 * @param  pEncryptedPart      [in]      Data to decrypt and digest.
 * @param  ulEncryptedPartLen  [in]      Length of data in bytes.
 * @param  pPart               [in]      Buffer to hold decrypted data.
 *                                       NULL indicates length required.
 * @param  pulPartLen          [in,out]  On in, length of buffer in bytes.
 *                                       On out, length of decrypted data in
 *                                       bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pEncryptedPart or pulDataLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_DecryptInit and C_DigestInit
 *          have not been successfully called.
 */
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pEncryptedPart == NULL || ulEncryptedPartLen == 0 ||
                                                           pulPartLen == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    (void)pPart;

    return CKR_OPERATION_NOT_INITIALIZED;
}

/**
 * Continue signing and encrypting multi-part data.
 *
 * @param  hSession             [in]      Handle of session.
 * @param  pPart                [in]      Data to sign and encrypt.
 * @param  ulPartLen            [in]      Length of data in bytes.
 * @param  pEncryptedPart       [in]      Buffer to hold encrypted data.
 *                                        NULL indicates length required.
 * @param  pulEncryptedPartLen  [in,out]  On in, length of buffer in bytes.
 *                                        On out, length of encrypted data in
 *                                        bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pPart or pulEncryptedPartLen is NULL or
 *          ulPartLen is 0.
 *          CKR_OPERATION_NOT_INITIALIZED when C_EncryptInit and C_SignInit
 *          have not been successfully called.
 */
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                          CK_BYTE_PTR pEncryptedPart,
                          CK_ULONG_PTR pulEncryptedPartLen)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pPart == NULL || ulPartLen == 0 || pulEncryptedPartLen == NULL)
        return CKR_ARGUMENTS_BAD;

    (void)pEncryptedPart;

    return CKR_OPERATION_NOT_INITIALIZED;
}

/**
 * Continue decrypting and verify multi-part data.
 *
 * @param  hSession            [in]      Handle of session.
 * @param  pEncryptedPart      [in]      Data to decrypt and verify.
 * @param  ulEncryptedPartLen  [in]      Length of data in bytes.
 * @param  pPart               [in]      Buffer to hold decrypted data.
 *                                       NULL indicates length required.
 * @param  pulPartLen          [in,out]  On in, length of buffer in bytes.
 *                                       On out, length of decrypted data in
 *                                       bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pEncryptedPart or pulDataLen is NULL.
 *          CKR_OPERATION_NOT_INITIALIZED when C_DecryptInit and C_VerifyInit
 *          have not been successfully called.
 */
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    WP11_Session* session;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pEncryptedPart == NULL || ulEncryptedPartLen == 0 ||
                                                           pulPartLen == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    (void)pPart;

    return CKR_OPERATION_NOT_INITIALIZED;
}

/**
 * Generate a symmetric key into a new key object.
 *
 * @param  hSession    [in]   Handle of session.
 * @param  pMechanism  [in]   Type of operation to perform with parameters.
 * @param  pTemplate   [in]   Array of attributes to create key object with.
 * @param  ulCount     [in]   Count of array elements.
 * @param  phKey       [out]  Handle to new key object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism, pTemplate or phKey is NULL.
 *          CKR_MECHANISM_PARAM_INVALID when mechanism's parameters are not
 *          valid for the operation.
 *          CKR_ATTRIBUTE_VALUE_INVALID when attribute value is not valid for
 *          data type.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when setting an attribute fails.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 *          CKR_OK on success.
 */
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv = CKR_OK;
    WP11_Session* session = NULL;
    WP11_Object* key = NULL;
    CK_BBOOL trueVar = CK_TRUE;
    CK_BBOOL getVar;
    CK_ULONG getVarLen = sizeof(CK_BBOOL);
    CK_KEY_TYPE keyType;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL || pTemplate == NULL || phKey == NULL)
        return CKR_ARGUMENTS_BAD;

    switch (pMechanism->mechanism) {
#ifndef NO_AES
        case CKM_AES_KEY_GEN:
            keyType = CKK_AES;
            break;
#endif
#ifdef HAVE_HKDF
        case CKM_HKDF_KEY_GEN:
            keyType = CKK_HKDF;
            break;
#endif
        case CKM_GENERIC_SECRET_KEY_GEN:
            keyType = CKK_GENERIC_SECRET;
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
    }

    if (rv == CKR_OK) {
        CK_ATTRIBUTE *lenAttr = NULL;
        if (pMechanism->pParameter != NULL ||
                                          pMechanism->ulParameterLen != 0) {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        FindAttributeType(pTemplate, ulCount, CKA_VALUE_LEN,
            &lenAttr);
        if (lenAttr == NULL)
            return CKR_TEMPLATE_INCOMPLETE;
        if (lenAttr->pValue == NULL)
            return CKR_ATTRIBUTE_VALUE_INVALID;
        if (lenAttr->ulValueLen != sizeof(CK_ULONG))
            return CKR_ATTRIBUTE_VALUE_INVALID;
        if (*(CK_ULONG*)lenAttr->pValue == 0)
            return CKR_ATTRIBUTE_VALUE_INVALID;


        rv = NewObject(session, keyType, CKO_SECRET_KEY, pTemplate, ulCount,
                       &key);
        if (rv == CKR_OK) {
            int ret = WP11_GenerateRandomKey(key,
                                             WP11_Session_GetSlot(session));
            if (ret != 0) {
                WP11_Object_Free(key);
                rv = CKR_FUNCTION_FAILED;
            }
            else {
               rv = AddObject(session, key, pTemplate, ulCount, phKey);
               if (rv != CKR_OK) {
                   WP11_Object_Free(key);
               }
            }
        }
    }
    if (rv == CKR_OK) {
        rv = WP11_Object_GetAttr(key, CKA_SENSITIVE, &getVar, &getVarLen);
        if ((rv == CKR_OK) && (getVar == CK_TRUE)) {
            rv = WP11_Object_SetAttr(key, CKA_ALWAYS_SENSITIVE, &trueVar,
                                     sizeof(CK_BBOOL));
        }
        if (rv == CKR_OK) {
            rv = WP11_Object_GetAttr(key, CKA_EXTRACTABLE, &getVar, &getVarLen);
            if ((rv == CKR_OK) && (getVar == CK_FALSE)) {
                rv = WP11_Object_SetAttr(key, CKA_NEVER_EXTRACTABLE, &trueVar,
                                     sizeof(CK_BBOOL));
            }
        }
    }

    return rv;
}


/**
 * Generate a public/private key pair into new key objects.
 *
 * @param  hSession                    [in]   Handle of session.
 * @param  pMechanism                  [in]   Type of operation to perform with
 *                                            parameters.
 * @param  pPublicKeyTemplate          [in]   Array of attributes to create
 *                                            public key object with.
 * @param  ulPublicKeyAttributeCount   [in]   Count of public key attriubues in
 *                                            the array.
 * @param  pPrivateKeyTemplate         [in]   Array of attributes to create
 *                                            private key object with.
 * @param  ulPrivateKeyAttributeCount  [in]   Count of private key attriubues in
 *                                            the array.
 * @param  phPublicKey                 [out]  Handle to new public key object.
 * @param  phPrivateKey                [out]  Handle to new private key object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism, pPublicKeyTemplate,
 *          pPrivateKeyTemplate, phPublicKey or phPrivateKey is NULL.
 *          CKR_MECHANISM_PARAM_INVALID when mechanism's parameters are not
 *          valid for the operation.
 *          CKR_ATTRIBUTE_VALUE_INVALID when attribute value is not valid for
 *          data type.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when setting an attribute fails.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 *          CKR_OK on success.
 */
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey,
                        CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    int ret;
    CK_RV rv = CKR_OK;
    WP11_Session* session = NULL;
    WP11_Object* pub = NULL;
    WP11_Object* priv = NULL;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL || pPublicKeyTemplate == NULL ||
                           pPrivateKeyTemplate == NULL || phPublicKey == NULL ||
                           phPrivateKey == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    switch (pMechanism->mechanism) {
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }

            *phPublicKey = *phPrivateKey = CK_INVALID_HANDLE;

            rv = NewObject(session, CKK_RSA, CKO_PUBLIC_KEY, pPublicKeyTemplate,
                           ulPublicKeyAttributeCount, &pub);
            if (rv == CKR_OK) {
                rv = NewObject(session, CKK_RSA, CKO_PRIVATE_KEY,
                                pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                &priv);
            }
            if (rv == CKR_OK) {
                ret = WP11_Rsa_GenerateKeyPair(pub, priv,
                                                 WP11_Session_GetSlot(session));
                if (ret != 0)
                    rv = CKR_FUNCTION_FAILED;
            }
            break;
#endif
#ifdef HAVE_ECC
       case CKM_EC_KEY_PAIR_GEN:
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }

            *phPublicKey = *phPrivateKey = CK_INVALID_HANDLE;

            rv = NewObject(session, CKK_EC, CKO_PUBLIC_KEY, pPublicKeyTemplate,
                                               ulPublicKeyAttributeCount, &pub);
             if (rv == CKR_OK) {
                rv = NewObject(session, CKK_EC, CKO_PRIVATE_KEY,
                                pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                &priv);
            }
            if (rv == CKR_OK) {
                ret = WP11_Ec_GenerateKeyPair(pub, priv,
                                                 WP11_Session_GetSlot(session));
                if (ret != 0)
                    rv = CKR_FUNCTION_FAILED;
            }
            break;
#endif
#ifndef NO_DH
        case CKM_DH_PKCS_KEY_PAIR_GEN:
            if (pMechanism->pParameter != NULL ||
                                              pMechanism->ulParameterLen != 0) {
                return CKR_MECHANISM_PARAM_INVALID;
            }

            *phPublicKey = *phPrivateKey = CK_INVALID_HANDLE;

            rv = NewObject(session, CKK_DH, CKO_PUBLIC_KEY, pPublicKeyTemplate,
                                               ulPublicKeyAttributeCount, &pub);
            if (rv == CKR_OK) {
                rv = NewObject(session, CKK_DH, CKO_PRIVATE_KEY,
                                pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                &priv);
            }
            if (rv == CKR_OK) {
                ret = WP11_Dh_GenerateKeyPair(pub, priv,
                                                 WP11_Session_GetSlot(session));
                if (ret != 0)
                    rv = CKR_FUNCTION_FAILED;
            }
            break;
#endif
        default:
            (void)ret;
            (void)ulPublicKeyAttributeCount;
            (void)ulPrivateKeyAttributeCount;
            return CKR_MECHANISM_INVALID;
    }

    if (rv == CKR_OK) {
        rv = AddObject(session, pub, pPublicKeyTemplate,
                                        ulPublicKeyAttributeCount, phPublicKey);
    }
#ifdef WOLFPKCS11_KEYPAIR_GEN_COMMON_LABEL
    if (rv == CKR_OK) {
        CK_ULONG len;
        ret = WP11_Object_GetAttr(pub, CKA_LABEL, NULL, &len);
        if (ret == 0 && len == 0) {
            CK_ULONG i;
            for (i = 0; i < ulPrivateKeyAttributeCount; i++) {
                CK_ATTRIBUTE* attr = &pPrivateKeyTemplate[i];
                if (attr->type == CKA_LABEL) {
                    WP11_Object_SetAttr(pub, CKA_LABEL, attr->pValue,
                                                              attr->ulValueLen);
                    break;
                }
            }
        }
    }
#endif
    if (rv == CKR_OK) {
        rv = AddObject(session, priv, pPrivateKeyTemplate,
                                      ulPrivateKeyAttributeCount, phPrivateKey);
    }

    if (pub != NULL && rv == CKR_OK) {
        rv = SetInitialStates(pub);
    }

    if (priv != NULL && rv == CKR_OK) {
        rv = SetInitialStates(priv);
    }

    if (rv != CKR_OK && pub != NULL)
        WP11_Object_Free(pub);
    if (rv != CKR_OK && priv != NULL)
        WP11_Object_Free(priv);

    return rv;
}

/**
 * Wrap a key using another key.
 *
 * @param  hSession          [in]      Handle of session.
 * @param  pMechanism        [in]      Type of operation to perform with
 *                                     parameters.
 * @param  hWrappingKey      [in]      Handle of key to wrap with.
 * @param  hKey              [in]      Handle of key to wrap.
 * @param  pWrappedKey       [in]      Buffer to hold wrapped key.
 * @param  pulWrappedKeyLen  [in,out]  On in, length of buffer.
 *                                     On out, length of wrapped key in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism or pulWrappedKeyLen is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when a key object handle is not valid.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 */
CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
                CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                CK_BYTE_PTR pWrappedKey,
                CK_ULONG_PTR pulWrappedKeyLen)
{
    int ret;
    CK_RV rv;
    WP11_Session* session = NULL;
    WP11_Object* key = NULL;
    WP11_Object* wrappingKey = NULL;
    CK_KEY_TYPE wrapkeyType;
    CK_KEY_TYPE  keyType = CKK_RSA;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    word32 serialSize = 0;
    byte* serialBuff = NULL;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL || pulWrappedKeyLen == NULL)
        return CKR_ARGUMENTS_BAD;

    if (! WP11_Session_IsRW(session))
        return CKR_SESSION_READ_ONLY;

    ret = WP11_Object_Find(session, hKey, &key);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    ret = WP11_Object_Find(session, hWrappingKey, &wrappingKey);
    if (ret != 0)
        return CKR_WRAPPING_KEY_HANDLE_INVALID;

    wrapkeyType = WP11_Object_GetType(wrappingKey);

    keyType = WP11_Object_GetType(key);

    keyClass = WP11_Object_GetClass(key);

    rv = CHECK_WRAPPABLE(keyClass, keyType);
    if (rv != CKR_OK)
        return rv;

    switch (keyType) {
#ifndef WOLFPKCS11_NO_STORE
#ifndef NO_RSA
        case CKK_RSA:
            ret = WP11_Rsa_SerializeKeyPTPKC8(key, NULL, &serialSize);
            if (ret != 0)
                return CKR_FUNCTION_FAILED;

            serialBuff = (byte*)XMALLOC(serialSize, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (serialBuff == NULL)
                return CKR_HOST_MEMORY;

            ret = WP11_Rsa_SerializeKeyPTPKC8(key, serialBuff, &serialSize);
            if (ret != 0) {
                rv = CKR_FUNCTION_FAILED;
                goto err_out;
            }
            break;
#endif
#ifndef NO_AES
        case CKK_AES:
#endif
        case CKK_GENERIC_SECRET:
            ret = WP11_Generic_SerializeKey(key, NULL, &serialSize);
            if (ret != 0) {
                rv = CKR_FUNCTION_FAILED;
                goto err_out;
            }

            serialBuff = (byte*)XMALLOC(serialSize, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (serialBuff == NULL)
                return CKR_HOST_MEMORY;

            ret = WP11_Generic_SerializeKey(key, serialBuff, &serialSize);
            if (ret != 0) {
                rv = CKR_FUNCTION_FAILED;
                goto err_out;
            }
            break;
#endif
        default:
            rv = CKR_KEY_NOT_WRAPPABLE;
            goto err_out;
    }

    switch (pMechanism->mechanism) {
#ifndef NO_AES
        /* These unwrap mechanisms can be supported with high level C_Encrypt */
#ifdef HAVE_AES_KEYWRAP
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_PAD:
#endif
        case CKM_AES_CBC_PAD:
            if (wrapkeyType != CKK_AES) {
                rv = CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
                goto err_out;
            }

            rv = C_EncryptInit(hSession, pMechanism, hWrappingKey);
            if (rv != CKR_OK)
                goto err_out;

            rv = C_Encrypt(hSession, serialBuff, serialSize, pWrappedKey, pulWrappedKeyLen);
            if (rv != CKR_OK)
                goto err_out;

            break;
#endif
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
    }
    (void)pWrappedKey;

err_out:

    if (serialBuff != NULL) {
        XMEMSET(serialBuff, 0, serialSize);
        XFREE(serialBuff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return rv;
}

/**
 * Unwrap a key using a wrap key.
 * Support only RSA private key wrapped by AESCBCPAD mechanism
 *
 * @param  hSession          [in]   Handle of session.
 * @param  pMechanism        [in]   Type of operation to perform with
 *                                  parameters.
 * @param  hUnwrappingKey    [in]   Handle of key to unwrap with.
 * @param  pWrappedKey       [in]   Buffer to hold wrapped key.
 * @param  pulWrappedKeyLen  [in]   Length of wrapped key in bytes.
 * @param  pTemplate         [in]   Array of attributes to create key object
 *                                  with.
 * @param  ulAttributeCount  [in]   Count of array elements.
 * @param  phKey             [out]  Handle of unwrapped key.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism or pulWrappedKeyLen is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when a key object handle is not valid.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 */
CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hUnwrappingKey,
                  CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
                  CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount,
                  CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv;
    int ret;
    WP11_Session* session = NULL;
    WP11_Object* unwrappingKey = NULL;
    CK_KEY_TYPE wrapkeyType;
    CK_KEY_TYPE       keyType = CKK_RSA;
    CK_OBJECT_CLASS   keyClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE*     attr = NULL;
    byte* workBuffer = NULL;
    CK_ULONG ulUnwrappedLen = ulWrappedKeyLen;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;

    if (!WP11_Session_IsRW(session))
        return CKR_SESSION_READ_ONLY;

    if (pMechanism == NULL || pWrappedKey == NULL || ulWrappedKeyLen == 0 ||
                                           pTemplate == NULL || phKey == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    *phKey = CK_INVALID_HANDLE;

    ret = WP11_Object_Find(session, hUnwrappingKey, &unwrappingKey);
    if (ret != 0)
        return CKR_UNWRAPPING_KEY_HANDLE_INVALID;

    rv = FindValidAttributeType(pTemplate, ulAttributeCount, CKA_KEY_TYPE,
        &attr, sizeof(CK_KEY_TYPE));
    if (rv != CKR_OK)
        return rv;

    keyType = *(CK_KEY_TYPE*)attr->pValue;
    rv = CHECK_KEYTYPE(keyType);
    if (rv != CKR_OK)
        return rv;

    rv = FindValidAttributeType(pTemplate, ulAttributeCount, CKA_CLASS, &attr,
        sizeof(CK_OBJECT_CLASS));
    if (rv != CKR_OK)
        return rv;

    keyClass = *(CK_OBJECT_CLASS*)attr->pValue;
    rv = CHECK_KEYCLASS(keyClass);
    if (rv != CKR_OK)
        return rv;

    rv = CHECK_WRAPPABLE(keyClass, keyType);
    if (rv != CKR_OK)
        return rv;

    wrapkeyType = WP11_Object_GetType(unwrappingKey);

    switch (pMechanism->mechanism) {
        /* These unwrap mechanisms can be supported with high level C_Decrypt */
#ifndef NO_AES
#ifdef HAVE_AES_KEYWRAP
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_PAD:
#endif
        case CKM_AES_CBC_PAD:

            if (wrapkeyType != CKK_AES)
                return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;

            workBuffer = (byte*)XMALLOC(ulWrappedKeyLen, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (workBuffer == NULL)
                return CKR_HOST_MEMORY;

            rv = C_DecryptInit(hSession, pMechanism, hUnwrappingKey);
            if (rv != CKR_OK)
                goto err_out;

            rv = C_Decrypt(hSession, pWrappedKey, ulWrappedKeyLen, workBuffer,
                &ulUnwrappedLen);
            if (rv != CKR_OK)
                goto err_out;

            break;
#endif
        default:
            rv = CKR_MECHANISM_INVALID;
            goto err_out;
    }

    switch (keyType) {
#ifndef NO_RSA
        case CKK_RSA:
            rv = AddRSAPrivateKeyObject(session, pTemplate, ulAttributeCount,
                workBuffer, ulUnwrappedLen, phKey);
            break;
#endif
#ifndef NO_AES
        case CKK_AES:
#endif
        case CKK_GENERIC_SECRET: {
            WP11_Object* keyObj = NULL;
            unsigned char* keyData[2] = {
                (unsigned char*)&ulUnwrappedLen,
                workBuffer
            };
            CK_ULONG keyDataLens[2] = { sizeof(CK_ULONG), ulUnwrappedLen };

            *phKey = CK_INVALID_HANDLE;
            rv = CreateObject(session, pTemplate, ulAttributeCount, &keyObj);
            if (rv == CKR_OK) {
                if (WP11_Object_SetSecretKey(keyObj, keyData, keyDataLens) != 0)
                    rv = CKR_FUNCTION_FAILED;
            }
            if (rv == CKR_OK) {
                rv = AddObject(session, keyObj, pTemplate, ulAttributeCount,
                               phKey);
            }
            if (rv != CKR_OK) {
                if (*phKey != CK_INVALID_HANDLE) {
                    WP11_Session_RemoveObject(session, keyObj);
                    *phKey = CK_INVALID_HANDLE;
                }
                if (keyObj != NULL) {
                    WP11_Object_Free(keyObj);
                }
            }
            break;
        }
        default:
            rv = CKR_KEY_NOT_WRAPPABLE;
            goto err_out;
    }

err_out:

    if (workBuffer != NULL) {
        XMEMSET(workBuffer, 0, ulWrappedKeyLen);
        XFREE(workBuffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return rv;
}

#if defined(HAVE_ECC) || !defined(NO_DH)
/**
 * Determine the key length of the object.
 *
 * @param  obj         [in]   Symmetric key object.
 * @param  len         [in]   Length of data to make key from.
 * @param  symmKeyLen  [out]  Length of symmetric key in bytes.
 * @return  0 on success.
 */
static int SymmKeyLen(WP11_Object* obj, word32 len, word32* symmKeyLen)
{
    int ret;
    word32 valueLen = 0;
    byte data[sizeof(CK_ULONG)];
    CK_ULONG dataLen = sizeof(data);

    ret = WP11_Object_GetAttr(obj, CKA_VALUE_LEN, data, &dataLen);
    if (ret != 0)
        return ret;

    valueLen = (word32)*(CK_ULONG*)data;

    switch (WP11_Object_GetType(obj)) {
        case CKK_AES:
        case CKK_HKDF:
        case CKK_GENERIC_SECRET:
        default:
            if (valueLen > 0 && valueLen <= len)
                len = valueLen;
            *symmKeyLen = len;
            break;
    }

    return ret;
}
#endif

static int SetKeyExtract(WP11_Session* session, byte* ptr, CK_ULONG length,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
                         CK_BBOOL isMac, CK_OBJECT_HANDLE* handle)
{
    WP11_Object* secret = NULL;
    int ret;
    word32 symmKeyLen;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    unsigned char* secretKeyData[2] = { NULL, NULL };
    CK_ULONG secretKeyLen[2] = { 0, 0 };

    ret = (int)CreateObject(session, pTemplate, ulAttributeCount, &secret);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    ret = SymmKeyLen(secret, (word32)length, &symmKeyLen);
    if (ret == 0) {
        /* Only use the bottom part of the secret for the key. */
        secretKeyData[1] = ptr + (length - symmKeyLen);
        secretKeyLen[1] = length;
        ret = WP11_Object_SetSecretKey(secret, secretKeyData, secretKeyLen);
        if (ret != CKR_OK)
            return CKR_FUNCTION_FAILED;
        ret = (int)AddObject(session, secret, pTemplate, ulAttributeCount,
            handle);
        if (ret != CKR_OK) {
            return ret;
        }
    }
    if ((ret == 0) && (isMac)) {
        ret = WP11_Object_SetAttr(secret, CKA_KEY_TYPE, (byte*)&keyType,
                                  sizeof(keyType));
        if (ret != CKR_OK)
            return ret;

        ret = WP11_Object_SetAttr(secret, CKA_DERIVE, &ckTrue,
                                  sizeof(CK_BBOOL));
        if (ret != CKR_OK)
            return ret;

        ret = WP11_Object_SetAttr(secret, CKA_ENCRYPT, &ckFalse,
                                  sizeof(CK_BBOOL));
        if (ret != CKR_OK)
            return ret;

        ret = WP11_Object_SetAttr(secret, CKA_DECRYPT, &ckFalse,
                                  sizeof(CK_BBOOL));
        if (ret != CKR_OK)
            return ret;

        ret = WP11_Object_SetAttr(secret, CKA_SIGN, &ckTrue,
                                  sizeof(CK_BBOOL));
        if (ret != CKR_OK)
            return ret;

        ret = WP11_Object_SetAttr(secret, CKA_VERIFY, &ckTrue,
                                  sizeof(CK_BBOOL));
        if (ret != CKR_OK)
            return ret;

        ret = WP11_Object_SetAttr(secret, CKA_WRAP, &ckFalse,
                                  sizeof(CK_BBOOL));
        if (ret != CKR_OK)
            return ret;

        ret = WP11_Object_SetAttr(secret, CKA_UNWRAP, &ckFalse,
                                  sizeof(CK_BBOOL));
        if (ret != CKR_OK)
            return ret;
    }

    return ret;
}

static int Tls12_Extract_Keys(WP11_Session* session,
                            CK_TLS12_KEY_MAT_PARAMS* tlsParams,
                            CK_ATTRIBUTE_PTR pTemplate,
                            CK_ULONG ulAttributeCount, byte* derivedKey)
{
    int ret = 0;
    unsigned char* ptr = derivedKey;
    CK_ULONG length;

    if (tlsParams == NULL) {
        return CKR_FUNCTION_FAILED;
    }

    /* Client MAC key */
    length = tlsParams->ulMacSizeInBits / 8;
    ret = SetKeyExtract(session, ptr, length, pTemplate,
            ulAttributeCount, CK_TRUE,
            &tlsParams->pReturnedKeyMaterial->hClientMacSecret);
    if (ret != 0) {
        return ret;
    }
    ptr += length;
    /* Server MAC key */
    ret = SetKeyExtract(session, ptr, length, pTemplate,
            ulAttributeCount, CK_TRUE,
            &tlsParams->pReturnedKeyMaterial->hServerMacSecret);
    if (ret != 0) {
        return ret;
    }
    ptr += length;
    /* Client key */
    length = tlsParams->ulKeySizeInBits / 8;
    ret = SetKeyExtract(session, ptr, length, pTemplate,
            ulAttributeCount, CK_FALSE,
            &tlsParams->pReturnedKeyMaterial->hClientKey);
    if (ret != 0) {
        return ret;
    }
    ptr += length;
    /* Server key */
    ret = SetKeyExtract(session, ptr, length, pTemplate,
            ulAttributeCount, CK_FALSE,
            &tlsParams->pReturnedKeyMaterial->hServerKey);
    if (ret != 0) {
        return ret;
    }
    ptr += length;
    /* Client IV */
    length = tlsParams->ulIVSizeInBits / 8;
    if (tlsParams->pReturnedKeyMaterial->pIVClient != NULL) {
        XMEMCPY(tlsParams->pReturnedKeyMaterial->pIVClient, ptr,
                length);
    }
    ptr += length;
    /* Server IV */
    if (tlsParams->pReturnedKeyMaterial->pIVServer != NULL) {
        XMEMCPY(tlsParams->pReturnedKeyMaterial->pIVServer, ptr,
                length);
    }
    return ret;
}

/**
 * Generate a symmetric key into a new key object.
 *
 * @param  hSession    [in]   Handle of session.
 * @param  pMechanism  [in]   Type of operation to perform with parameters.
 * @param  hBaseKey    [in]   Handle to base key object.
 * @param  pTemplate   [in]   Array of attributes to create key object with.
 * @param  ulCount     [in]   Count of array elements.
 * @param  phKey       [out]  Handle to new key object.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pMechanism, pTemplate or phKey is NULL.
 *          CKR_OBJECT_HANDLE_INVALID when key object handle is not valid.
 *          CKR_MECHANISM_PARAM_INVALID when mechanism's parameters are not
 *          valid for the operation.
 *          CKR_ATTRIBUTE_VALUE_INVALID when attribute value is not valid for
 *          data type.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when setting an attribute fails.
 *          CKR_MECHANISM_INVALID when the mechanism is not supported with this
 *          type of operation.
 *          CKR_OK on success.
 */
CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hBaseKey,
                  CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount,
                  CK_OBJECT_HANDLE_PTR phKey)
{
    int ret;
    CK_RV rv = CKR_OK;
    WP11_Session* session;
    WP11_Object* obj = NULL;
#if defined(HAVE_ECC) || !defined(NO_DH) || defined(WOLFPKCS11_HKDF)
    byte* derivedKey = NULL;
    word32 keyLen;
    word32 symmKeyLen;
    unsigned char* secretKeyData[2] = { NULL, NULL };
    CK_ULONG secretKeyLen[2] = { 0, 0 };
#endif

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL || pTemplate == NULL)
        return CKR_ARGUMENTS_BAD;
    /* phKey can be NULL for CKM_TLS12_KEY_AND_MAC_DERIVE as it is ignored */
    if ((phKey == NULL) &&
        (pMechanism->mechanism != CKM_TLS12_KEY_AND_MAC_DERIVE))
        return CKR_ARGUMENTS_BAD;

    ret = WP11_Object_Find(session, hBaseKey, &obj);
    if (ret != 0)
        return CKR_OBJECT_HANDLE_INVALID;

    switch (pMechanism->mechanism) {
#ifdef HAVE_ECC
        case CKM_ECDH1_DERIVE: {
            CK_ECDH1_DERIVE_PARAMS* params;

            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS))
                 return CKR_MECHANISM_PARAM_INVALID;
            params = (CK_ECDH1_DERIVE_PARAMS*)pMechanism->pParameter;
            if (params->pPublicData == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (params->ulPublicDataLen == 0)
                return CKR_MECHANISM_PARAM_INVALID;
            if (params->kdf != CKD_NULL)
                return CKR_MECHANISM_PARAM_INVALID;

            keyLen = (word32)(params->ulPublicDataLen / 2);
            derivedKey = (byte*)XMALLOC(keyLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derivedKey == NULL)
                return CKR_DEVICE_MEMORY;

            ret = WP11_EC_Derive(params->pPublicData,
                                       (int)params->ulPublicDataLen, derivedKey,
                                       keyLen, obj);
            if (ret != 0)
                rv = CKR_FUNCTION_FAILED;
            break;
        }
#endif
#ifdef WOLFPKCS11_HKDF
        case CKM_HKDF_DERIVE:
        case CKM_HKDF_DATA: {
            CK_HKDF_PARAMS_PTR kdfParams;
            CK_ATTRIBUTE *lenAttr = NULL;

            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen != sizeof(CK_HKDF_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;
            kdfParams = (CK_HKDF_PARAMS_PTR)pMechanism->pParameter;
            if (!kdfParams->bExpand && !kdfParams->bExtract)
                return CKR_MECHANISM_PARAM_INVALID;

            FindAttributeType(pTemplate, ulAttributeCount, CKA_VALUE_LEN,
                &lenAttr);
            if (kdfParams->bExpand) {
                if (!lenAttr) {
                    return CKR_MECHANISM_PARAM_INVALID;
                }
                keyLen = *(word32*)lenAttr->pValue;
            }
            else {
                keyLen = WC_MAX_DIGEST_SIZE;
            }
            derivedKey = (byte*)XMALLOC(keyLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derivedKey == NULL)
                return CKR_DEVICE_MEMORY;

            ret = WP11_KDF_Derive(session, kdfParams, derivedKey, &keyLen, obj);

            if (ret != 0)
                rv = CKR_FUNCTION_FAILED;
            break;
        }
#endif
#ifndef NO_DH
        case CKM_DH_PKCS_DERIVE:
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen == 0)
                return CKR_MECHANISM_PARAM_INVALID;

            keyLen = (word32)pMechanism->ulParameterLen;
            derivedKey = (byte*)XMALLOC(keyLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derivedKey == NULL)
                return CKR_DEVICE_MEMORY;

            ret = WP11_Dh_Derive((unsigned char*)pMechanism->pParameter,
                                    (int)pMechanism->ulParameterLen, derivedKey,
                                    &keyLen, obj);
            if (ret != 0)
                rv = CKR_FUNCTION_FAILED;
            break;
#endif
#ifndef NO_AES
#ifdef HAVE_AES_CBC
        case CKM_AES_CBC_ENCRYPT_DATA: {
            CK_AES_CBC_ENCRYPT_DATA_PARAMS* params;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen !=
                    sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;
            params = (CK_AES_CBC_ENCRYPT_DATA_PARAMS*)pMechanism->pParameter;
            if (params->length % 16)
                return CKR_MECHANISM_PARAM_INVALID;

            keyLen = (word32)params->length;
            derivedKey = (byte*)XMALLOC(keyLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derivedKey == NULL)
                return CKR_DEVICE_MEMORY;

            ret = WP11_AesCbc_DeriveKey(params->pData, (word32)params->length,
                    derivedKey, params->iv, obj);
            if (ret != 0)
                rv = CKR_FUNCTION_FAILED;
            break;
        }
#endif
#endif
#ifdef WOLFSSL_HAVE_PRF
        case CKM_TLS12_KEY_AND_MAC_DERIVE:
        {
            CK_TLS12_KEY_MAT_PARAMS* tlsParams = NULL;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen !=
                sizeof(CK_TLS12_KEY_MAT_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;
            tlsParams = (CK_TLS12_KEY_MAT_PARAMS*) pMechanism->pParameter;
            if (tlsParams->pReturnedKeyMaterial == NULL)
                return CKR_MECHANISM_PARAM_INVALID;

            keyLen = (word32)(2 * tlsParams->ulMacSizeInBits) +
                     (word32)(2 * tlsParams->ulKeySizeInBits) +
                     (word32)(2 * tlsParams->ulIVSizeInBits);
            if (keyLen == 0)
                return CKR_MECHANISM_PARAM_INVALID;
            if ((keyLen % 8) != 0)
                return CKR_MECHANISM_PARAM_INVALID;
            keyLen /= 8;

            derivedKey = (byte*)XMALLOC(keyLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derivedKey == NULL)
                return CKR_DEVICE_MEMORY;
            ret = WP11_Tls12_Master_Key_Derive(&tlsParams->RandomInfo,
                                               tlsParams->prfHashMechanism,
                                               "key expansion", 13,
                                               derivedKey, keyLen, CK_FALSE,
                                               obj);
            if (ret == 0)
                ret = Tls12_Extract_Keys(session, tlsParams, pTemplate,
                                         ulAttributeCount, derivedKey);

            /* Freeing here so that we don't attempt to generate a key at the
             * end of the function */
            XMEMSET(derivedKey, 0, keyLen);
            XFREE(derivedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            derivedKey = NULL;

            if (ret != 0)
                rv = CKR_FUNCTION_FAILED;
            break;
        }
        case CKM_TLS12_MASTER_KEY_DERIVE:
        case CKM_TLS12_MASTER_KEY_DERIVE_DH:
        {
            CK_TLS12_MASTER_KEY_DERIVE_PARAMS* prfParams;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen !=
                sizeof(CK_TLS12_MASTER_KEY_DERIVE_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;
            prfParams = (CK_TLS12_MASTER_KEY_DERIVE_PARAMS*)
                pMechanism->pParameter;
            if (prfParams->RandomInfo.pClientRandom == NULL ||
                prfParams->RandomInfo.pServerRandom == NULL)
                return CKR_MECHANISM_PARAM_INVALID;

            if (pMechanism->mechanism == CKM_TLS12_MASTER_KEY_DERIVE) {
                if (prfParams->pVersion == NULL)
                    return CKR_MECHANISM_PARAM_INVALID;
                if ((prfParams->pVersion->major != 3) ||
                    (prfParams->pVersion->minor != 3))
                    return CKR_MECHANISM_INVALID;
            }

            keyLen = PRF_KEY_SIZE;
            derivedKey = (byte*)XMALLOC(keyLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derivedKey == NULL)
                return CKR_DEVICE_MEMORY;

            ret = WP11_Tls12_Master_Key_Derive(&prfParams->RandomInfo,
                                               prfParams->prfHashMechanism,
                                               "master secret", 13,
                                               derivedKey, keyLen, CK_TRUE,
                                               obj);

            if (ret != 0)
                rv = CKR_FUNCTION_FAILED;
            break;
        }
#ifdef WOLFPKCS11_NSS
        case CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE:
        case CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH:
        {
            CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS* nssParams = NULL;
            if (pMechanism->pParameter == NULL)
                return CKR_MECHANISM_PARAM_INVALID;
            if (pMechanism->ulParameterLen !=
                sizeof(CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS))
                return CKR_MECHANISM_PARAM_INVALID;
            nssParams = (CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS*)
                pMechanism->pParameter;

            keyLen = PRF_KEY_SIZE;
            derivedKey = (byte*)XMALLOC(keyLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derivedKey == NULL)
                return CKR_DEVICE_MEMORY;

            ret = WP11_Nss_Tls12_Master_Key_Derive(nssParams->pSessionHash,
                                                   nssParams->ulSessionHashLen,
                                                   nssParams->prfHashMechanism,
                                                   "extended master secret", 22,
                                                   derivedKey, keyLen, obj);

            if (ret != 0)
                rv = CKR_FUNCTION_FAILED;
            break;
        }
#endif
#endif
        default:
            (void)ulAttributeCount;
            return CKR_MECHANISM_INVALID;
    }

#if defined(HAVE_ECC) || !defined(NO_DH) || defined(WOLFPKCS11_HKDF) || \
    (!defined(NO_AES) && defined(HAVE_AES_CBC))
    if ((ret == 0) && (derivedKey != NULL)) {
        rv = CreateObject(session, pTemplate, ulAttributeCount, &obj);
        if (rv == CKR_OK) {
            ret = SymmKeyLen(obj, keyLen, &symmKeyLen);
            if (ret == 0) {
                /* Only use the bottom part of the secret for the key. */
                secretKeyData[1] = derivedKey + (keyLen - symmKeyLen);
                secretKeyLen[1] = keyLen;
                ret = WP11_Object_SetSecretKey(obj, secretKeyData,
                                                secretKeyLen);
                if (ret != 0)
                    rv = CKR_FUNCTION_FAILED;
                if (ret == 0) {
                    rv = AddObject(session, obj, pTemplate,
                                    ulAttributeCount, phKey);
                }
            }
            else {
                WP11_Object_Free(obj);
                rv = ret;
            }
        }
    }

    if (rv == CKR_OK) {
        rv = SetInitialStates(obj);
    }

    if (derivedKey != NULL) {
        XMEMSET(derivedKey, 0, keyLen);
        XFREE(derivedKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return rv;
}

/**
 * Seed the token's random number generator.
 *
 * @param  hSession   [in]  Handle of session.
 * @param  pSeed      [in]  Seed data.
 * @param  ulSeedLen  [in]  Length of seed data in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pSeed is NULL.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when seeding the random fails.
 *          CKR_OK on success.
 */
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                   CK_ULONG ulSeedLen)
{
    int ret;
    WP11_Session* session;
    WP11_Slot* slot;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pSeed == NULL)
        return CKR_ARGUMENTS_BAD;

    slot = WP11_Session_GetSlot(session);
    ret = WP11_Slot_SeedRandom(slot, pSeed, (int)ulSeedLen);
    if (ret == MEMORY_E)
        return CKR_DEVICE_MEMORY;
    if (ret != 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}

/**
 * Generate random data using token's random number generator.
 *
 * @param  hSession     [in]  Handle of session.
 * @param  pRandomData  [in]  Buffer to hold random data.
 * @param  ulRandomLen  [in]  Length of buffer in bytes.
 * @return  CKR_CRYPTOKI_NOT_INITIALIZED when library not initialized.
 *          CKR_SESSION_HANDLE_INVALID when session handle is not valid.
 *          CKR_ARGUMENTS_BAD when pRandomData is NULL.
 *          CKR_DEVICE_MEMORY when dynamic memory allocation fails.
 *          CKR_FUNCTION_FAILED when generating random data fails.
 *          CKR_OK on success.
 */
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    int ret;
    WP11_Session* session;
    WP11_Slot* slot;

    if (!WP11_Library_IsInitialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (WP11_Session_Get(hSession, &session) != 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pRandomData == NULL)
        return CKR_ARGUMENTS_BAD;

    slot = WP11_Session_GetSlot(session);
    ret = WP11_Slot_GenerateRandom(slot, pRandomData, (int)ulRandomLen);
    if (ret == MEMORY_E)
        return CKR_DEVICE_MEMORY;
    if (ret != 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}
