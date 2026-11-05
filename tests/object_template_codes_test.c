/* object_template_codes_test.c
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
 * Return codes for bad key handles, templates, object creation, key
 * generation, derivation and unwrapping.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/object_template_codes_test"

#define BAD_HANDLE ((CK_OBJECT_HANDLE)0x0DEADBEE)

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS dataClass = CKO_DATA;
static CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
static CK_BYTE keyBytes[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

#define TMPL_CNT(t) (sizeof(t) / sizeof(*(t)))

static void create_expect(CK_SESSION_HANDLE session, CK_ATTRIBUTE* tmpl,
                          CK_ULONG cnt, CK_RV expected, const char* what)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;

    rv = funcList->C_CreateObject(session, tmpl, cnt, &obj);
    CHECK_RV(rv, what, expected);
    if (rv == CKR_OK)
        funcList->C_DestroyObject(session, obj);
}

static CK_RV create_generic_key(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE* key)
{
    CK_RV rv;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_DERIVE,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_SIGN,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,    keyBytes,     sizeof(keyBytes)    },
    };

    rv = funcList->C_CreateObject(session, tmpl, TMPL_CNT(tmpl), key);
    CHECK_RV(rv, "create generic secret key", CKR_OK);
    return rv;
}

static void test_key_handles(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    CK_MECHANISM digest = { CKM_SHA256, NULL, 0 };
    CK_MECHANISM wrap = { CKM_AES_KEY_WRAP, NULL, 0 };
    CK_MECHANISM derive = { CKM_ECDH1_DERIVE, NULL, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE out;
    CK_ULONG len = 0;
    CK_ULONG valueLen = 16;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_VALUE_LEN, &valueLen,    sizeof(valueLen)    },
    };

    printf("\n--- unresolved key handles ---\n");

    rv = funcList->C_EncryptInit(session, &mech, BAD_HANDLE);
    CHECK_RV(rv, "C_EncryptInit", CKR_KEY_HANDLE_INVALID);
    rv = funcList->C_DecryptInit(session, &mech, BAD_HANDLE);
    CHECK_RV(rv, "C_DecryptInit", CKR_KEY_HANDLE_INVALID);
    rv = funcList->C_SignInit(session, &mech, BAD_HANDLE);
    CHECK_RV(rv, "C_SignInit", CKR_KEY_HANDLE_INVALID);
    rv = funcList->C_VerifyInit(session, &mech, BAD_HANDLE);
    CHECK_RV(rv, "C_VerifyInit", CKR_KEY_HANDLE_INVALID);
    rv = funcList->C_SignRecoverInit(session, &mech, BAD_HANDLE);
    CHECK_RV(rv, "C_SignRecoverInit", CKR_KEY_HANDLE_INVALID);
#ifndef NO_RSA
    rv = funcList->C_VerifyRecoverInit(session, &mech, BAD_HANDLE);
    CHECK_RV(rv, "C_VerifyRecoverInit", CKR_KEY_HANDLE_INVALID);
#endif
#ifndef NO_SHA256
    rv = funcList->C_DigestInit(session, &digest);
    CHECK_RV(rv, "C_DigestInit", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_DigestKey(session, BAD_HANDLE);
        CHECK_RV(rv, "C_DigestKey", CKR_KEY_HANDLE_INVALID);
    }
#else
    (void)digest;
#endif

    if (create_generic_key(session, &key) != CKR_OK)
        return;
    rv = funcList->C_WrapKey(session, &wrap, key, BAD_HANDLE, NULL, &len);
    CHECK_RV(rv, "C_WrapKey key to wrap", CKR_KEY_HANDLE_INVALID);
    rv = funcList->C_DeriveKey(session, &derive, BAD_HANDLE, tmpl,
                               TMPL_CNT(tmpl), &out);
    CHECK_RV(rv, "C_DeriveKey base key", CKR_KEY_HANDLE_INVALID);
    funcList->C_DestroyObject(session, key);
}

#ifndef NO_AES
static void test_fixed_size_attrs(CK_SESSION_HANDLE session)
{
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BYTE wide[sizeof(CK_ULONG) * 2];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_VALUE,    keyBytes,     16                  },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
    };
    CK_ULONG cnt = TMPL_CNT(tmpl);

    printf("\n--- fixed-size attribute lengths ---\n");
    XMEMSET(wide, 0, sizeof(wide));

    create_expect(session, tmpl, cnt, CKR_OK, "AES key (control)");

    tmpl[5].type = CKA_ENCRYPT;
    tmpl[5].pValue = wide;
    tmpl[5].ulValueLen = 4;
    create_expect(session, tmpl, cnt, CKR_ATTRIBUTE_VALUE_INVALID,
                  "CKA_ENCRYPT of 4 bytes");
    tmpl[5].type = CKA_VALUE_LEN;
    tmpl[5].ulValueLen = sizeof(CK_ULONG) * 2;
    create_expect(session, tmpl, cnt, CKR_ATTRIBUTE_VALUE_INVALID,
                  "CKA_VALUE_LEN of two CK_ULONGs");
    tmpl[5].type = CKA_START_DATE;
    tmpl[5].ulValueLen = 4;
    create_expect(session, tmpl, cnt, CKR_ATTRIBUTE_VALUE_INVALID,
                  "CKA_START_DATE of 4 bytes");
}
#endif

static void test_get_attr_short_buffer(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    char label[] = "0123456789";
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
        { CKA_TOKEN, &ckFalse,   sizeof(ckFalse)   },
        { CKA_LABEL, label,      sizeof(label) - 1 },
    };
    CK_OBJECT_CLASS cls = 0;
    char buf[4];
    CK_ATTRIBUTE get[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_LABEL, buf,  sizeof(buf) },
    };

    printf("\n--- C_GetAttributeValue short buffer ---\n");

    rv = funcList->C_CreateObject(session, tmpl, TMPL_CNT(tmpl), &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = funcList->C_GetAttributeValue(session, obj, get, TMPL_CNT(get));
    CHECK_RV(rv, "label in a 4-byte buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(get[0].ulValueLen == sizeof(cls) && cls == CKO_DATA,
               "class still returned");
    CHECK_TRUE(get[1].ulValueLen == CK_UNAVAILABLE_INFORMATION,
               "short label length is CK_UNAVAILABLE_INFORMATION");
    funcList->C_DestroyObject(session, obj);
}

#if !defined(NO_RSA) || defined(HAVE_ECC)
static void check_get_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                           CK_ATTRIBUTE_TYPE type, CK_RV expected,
                           const char* what)
{
    CK_RV rv;
    CK_BYTE buf[512];
    CK_ATTRIBUTE get = { type, buf, sizeof(buf) };

    rv = funcList->C_GetAttributeValue(session, obj, &get, 1);
    CHECK_RV(rv, what, expected);
    if (expected != CKR_OK) {
        CHECK_TRUE(get.ulValueLen == CK_UNAVAILABLE_INFORMATION,
                   "length is CK_UNAVAILABLE_INFORMATION");
    }
}
#endif

#ifndef NO_RSA
static void test_rsa_public_attrs(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,           &pubClass,        sizeof(pubClass)         },
        { CKA_KEY_TYPE,        &rsaType,         sizeof(rsaType)          },
        { CKA_TOKEN,           &ckFalse,         sizeof(ckFalse)          },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,            &privClass,        sizeof(privClass)         },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_TOKEN,            &ckFalse,          sizeof(ckFalse)           },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
        { CKA_SENSITIVE,        &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
    };

    printf("\n--- RSA public key private attributes ---\n");

    rv = funcList->C_CreateObject(session, pubTmpl, TMPL_CNT(pubTmpl), &pub);
    CHECK_RV(rv, "create RSA public key", CKR_OK);
    if (rv == CKR_OK) {
        check_get_attr(session, pub, CKA_MODULUS, CKR_OK, "modulus");
        check_get_attr(session, pub, CKA_PRIVATE_EXPONENT,
                       CKR_ATTRIBUTE_TYPE_INVALID, "public key d");
        check_get_attr(session, pub, CKA_PRIME_1, CKR_ATTRIBUTE_TYPE_INVALID,
                       "public key p");
        check_get_attr(session, pub, CKA_COEFFICIENT,
                       CKR_ATTRIBUTE_TYPE_INVALID, "public key u");
        funcList->C_DestroyObject(session, pub);
    }

    rv = funcList->C_CreateObject(session, privTmpl, TMPL_CNT(privTmpl),
                                  &priv);
    CHECK_RV(rv, "create sensitive RSA private key", CKR_OK);
    if (rv == CKR_OK) {
        check_get_attr(session, priv, CKA_PRIVATE_EXPONENT,
                       CKR_ATTRIBUTE_SENSITIVE, "sensitive private key d");
        funcList->C_DestroyObject(session, priv);
    }
}
#endif

#ifdef HAVE_ECC
static void test_ec_public_attrs(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &pubClass,       sizeof(pubClass)        },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)          },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_EC_POINT,  ecc_p256_pub,    sizeof(ecc_p256_pub)    },
    };

    printf("\n--- EC public key CKA_VALUE ---\n");

    rv = funcList->C_CreateObject(session, tmpl, TMPL_CNT(tmpl), &pub);
    CHECK_RV(rv, "create EC public key", CKR_OK);
    if (rv != CKR_OK)
        return;
    check_get_attr(session, pub, CKA_EC_POINT, CKR_OK, "EC point");
    check_get_attr(session, pub, CKA_VALUE, CKR_ATTRIBUTE_TYPE_INVALID,
                   "public key CKA_VALUE");
    funcList->C_DestroyObject(session, pub);
}
#endif

static void test_create_object(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS badClass = 0x12345;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_ULONG zeroLen = 0;
    CK_ATTRIBUTE badClassTmpl[] = {
        { CKA_CLASS, &badClass, sizeof(badClass) },
        { CKA_TOKEN, &ckFalse,  sizeof(ckFalse)  },
    };
    CK_ATTRIBUTE noClassTmpl[] = {
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
        { CKA_VALUE,    keyBytes,     16                  },
    };
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,    keyBytes,     16                  },
        { CKA_VALUE_LEN, &zeroLen,    sizeof(zeroLen)     },
    };

    printf("\n--- C_CreateObject class and value checks ---\n");

    create_expect(session, badClassTmpl, TMPL_CNT(badClassTmpl),
                  CKR_ATTRIBUTE_VALUE_INVALID, "undefined CKA_CLASS");
    create_expect(session, noClassTmpl, TMPL_CNT(noClassTmpl),
                  CKR_TEMPLATE_INCOMPLETE, "no CKA_CLASS");
#if !defined(NO_AES) && !defined(WOLFPKCS11_NSS)
    create_expect(session, aesTmpl, TMPL_CNT(aesTmpl) - 1, CKR_OK,
                  "16-byte AES key (control)");
    create_expect(session, aesTmpl, TMPL_CNT(aesTmpl),
                  CKR_ATTRIBUTE_VALUE_INVALID, "AES key with CKA_VALUE_LEN 0");
    aesTmpl[5].ulValueLen = 13;
    create_expect(session, aesTmpl, TMPL_CNT(aesTmpl) - 1,
                  CKR_ATTRIBUTE_VALUE_INVALID, "13-byte AES key");
#else
    (void)aesTmpl;
    (void)zeroLen;
#endif
}

#ifdef HAVE_ECC
static void test_ec_params(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_KEY_TYPE ecType = CKK_EC;
    CK_BYTE truncated[] = { 0x06, 0x05, 0x2B, 0x81 };
    CK_BYTE octets[] = { 0x04, 0x02, 0x01, 0x02 };
    CK_BYTE unknownOid[] = { 0x06, 0x03, 0x2A, 0x03, 0x04 };
    CK_BYTE emptyOid[] = { 0x06, 0x00 };
    CK_BYTE bigPoint[sizeof(ecc_p256_pub)];
    CK_BYTE offCurve[sizeof(ecc_p256_pub)];
    CK_BYTE explicitParams[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    CK_BYTE explicitLong[3 + 0x80];
    CK_BYTE seqTag[] = { 0x30 };
    CK_BYTE shortSeq[] = { 0x30, 0x05, 0x02 };
    CK_BYTE openOid[] = { 0x06, 0x01, 0x80 };
    CK_BYTE paddedOid[] = { 0x06, 0x03, 0x80, 0x01, 0x01 };
    CK_OBJECT_HANDLE pub, priv;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, truncated, sizeof(truncated) },
        { CKA_TOKEN,     &ckFalse,  sizeof(ckFalse)   },
        { CKA_VERIFY,    &ckTrue,   sizeof(ckTrue)    },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &ckFalse, sizeof(ckFalse) },
        { CKA_PRIVATE, &ckFalse, sizeof(ckFalse) },
        { CKA_SIGN,    &ckTrue,  sizeof(ckTrue)  },
    };
    CK_BYTE bigValue[32];
    CK_ATTRIBUTE privTmplBig[] = {
        { CKA_CLASS,     &privClass,      sizeof(privClass)       },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)          },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_PRIVATE,   &ckFalse,        sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,     bigValue,        sizeof(bigValue)        },
    };
    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,     &pubClass,    sizeof(pubClass)     },
        { CKA_KEY_TYPE,  &ecType,      sizeof(ecType)       },
        { CKA_TOKEN,     &ckFalse,     sizeof(ckFalse)      },
        { CKA_EC_PARAMS, unknownOid,   sizeof(unknownOid)   },
        { CKA_EC_POINT,  ecc_p256_pub, sizeof(ecc_p256_pub) },
    };

    printf("\n--- CKA_EC_PARAMS ---\n");

    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
            TMPL_CNT(pubTmpl), privTmpl, TMPL_CNT(privTmpl), &pub, &priv);
    CHECK_RV(rv, "truncated OID", CKR_ATTRIBUTE_VALUE_INVALID);
    pubTmpl[0].pValue = octets;
    pubTmpl[0].ulValueLen = sizeof(octets);
    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
            TMPL_CNT(pubTmpl), privTmpl, TMPL_CNT(privTmpl), &pub, &priv);
    CHECK_RV(rv, "OCTET STRING params", CKR_ATTRIBUTE_VALUE_INVALID);
    pubTmpl[0].pValue = unknownOid;
    pubTmpl[0].ulValueLen = sizeof(unknownOid);
    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
            TMPL_CNT(pubTmpl), privTmpl, TMPL_CNT(privTmpl), &pub, &priv);
    CHECK_RV(rv, "unknown curve keygen", CKR_CURVE_NOT_SUPPORTED);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_CURVE_NOT_SUPPORTED, "unknown curve public key");
    createTmpl[3].pValue = emptyOid;
    createTmpl[3].ulValueLen = sizeof(emptyOid);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_ATTRIBUTE_VALUE_INVALID, "empty OID");
    createTmpl[3].pValue = explicitParams;
    createTmpl[3].ulValueLen = sizeof(explicitParams);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_CURVE_NOT_SUPPORTED, "explicit curve parameters");
    XMEMSET(explicitLong, 0x05, sizeof(explicitLong));
    explicitLong[0] = 0x30;
    explicitLong[1] = 0x81;
    explicitLong[2] = 0x80;
    createTmpl[3].pValue = explicitLong;
    createTmpl[3].ulValueLen = sizeof(explicitLong);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_CURVE_NOT_SUPPORTED, "long explicit curve parameters");
    createTmpl[3].pValue = seqTag;
    createTmpl[3].ulValueLen = sizeof(seqTag);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_ATTRIBUTE_VALUE_INVALID, "SEQUENCE tag alone");
    createTmpl[3].pValue = shortSeq;
    createTmpl[3].ulValueLen = sizeof(shortSeq);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_ATTRIBUTE_VALUE_INVALID, "truncated SEQUENCE");
    createTmpl[3].pValue = openOid;
    createTmpl[3].ulValueLen = sizeof(openOid);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_ATTRIBUTE_VALUE_INVALID, "unterminated OID subidentifier");
    createTmpl[3].pValue = paddedOid;
    createTmpl[3].ulValueLen = sizeof(paddedOid);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_ATTRIBUTE_VALUE_INVALID, "padded OID subidentifier");
    createTmpl[3].pValue = ecc_p256_params;
    createTmpl[3].ulValueLen = sizeof(ecc_p256_params);
    createTmpl[4].pValue = ecc_p256_point;
    createTmpl[4].ulValueLen = sizeof(ecc_p256_point);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_ATTRIBUTE_VALUE_INVALID, "EC point without DER wrapping");
    XMEMSET(bigPoint, 0xFF, sizeof(bigPoint));
    bigPoint[0] = 0x04;
    bigPoint[1] = 0x41;
    bigPoint[2] = 0x04;
    createTmpl[4].pValue = bigPoint;
    createTmpl[4].ulValueLen = sizeof(bigPoint);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_ATTRIBUTE_VALUE_INVALID, "EC point coordinates above p");
    XMEMCPY(offCurve, ecc_p256_pub, sizeof(offCurve));
    offCurve[sizeof(offCurve) - 1] ^= 0x01;
    createTmpl[4].pValue = offCurve;
    createTmpl[4].ulValueLen = sizeof(offCurve);
    create_expect(session, createTmpl, TMPL_CNT(createTmpl),
                  CKR_ATTRIBUTE_VALUE_INVALID, "EC point off the curve");
    XMEMSET(bigValue, 0xFF, sizeof(bigValue));
    create_expect(session, privTmplBig, TMPL_CNT(privTmplBig),
                  CKR_ATTRIBUTE_VALUE_INVALID, "EC private value above order");
    XMEMSET(bigValue, 0, sizeof(bigValue));
    create_expect(session, privTmplBig, TMPL_CNT(privTmplBig),
                  CKR_ATTRIBUTE_VALUE_INVALID, "zero EC private value");
}
#endif

#if (!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)) || defined(WOLFPKCS11_HKDF)
static CK_SLOT_ID session_slot(CK_SESSION_HANDLE session)
{
    CK_SESSION_INFO info;

    XMEMSET(&info, 0, sizeof(info));
    funcList->C_GetSessionInfo(session, &info);
    return info.slotID;
}
#endif

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
static void test_rsa_keygen(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM_INFO info;
    CK_ULONG bits = RSA_MIN_SIZE - 8;
    CK_BYTE bigExp[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                         0x01 };
    CK_BYTE evenExp[] = { 0x01, 0x00, 0x00 };
    CK_BYTE zeroExp[] = { 0x00 };
    CK_OBJECT_HANDLE pub, priv;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_MODULUS_BITS, &bits,   sizeof(bits)    },
        { CKA_TOKEN,        &ckFalse, sizeof(ckFalse) },
        { CKA_VERIFY,       &ckTrue,  sizeof(ckTrue)  },
    };
    CK_ATTRIBUTE expTmpl[] = {
        { CKA_MODULUS_BITS,    &bits,   sizeof(bits)    },
        { CKA_TOKEN,           &ckFalse, sizeof(ckFalse) },
        { CKA_VERIFY,          &ckTrue,  sizeof(ckTrue)  },
        { CKA_PUBLIC_EXPONENT, bigExp,   sizeof(bigExp)  },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &ckFalse, sizeof(ckFalse) },
        { CKA_PRIVATE, &ckFalse, sizeof(ckFalse) },
        { CKA_SIGN,    &ckTrue,  sizeof(ckTrue)  },
    };

    printf("\n--- RSA key generation size and exponent ---\n");

    rv = funcList->C_GetMechanismInfo(session_slot(session),
                                      CKM_RSA_PKCS_KEY_PAIR_GEN, &info);
    CHECK_RV(rv, "C_GetMechanismInfo", CKR_OK);
    CHECK_TRUE(rv == CKR_OK && info.ulMinKeySize == (CK_ULONG)RSA_MIN_SIZE &&
               info.ulMaxKeySize == (CK_ULONG)RSA_MAX_SIZE,
               "sizes are wolfSSL's RSA_MIN_SIZE and RSA_MAX_SIZE");
    rv = funcList->C_GetMechanismInfo(session_slot(session), CKM_RSA_PKCS,
                                      &info);
    CHECK_TRUE(rv == CKR_OK && info.ulMinKeySize == 1024 &&
               info.ulMaxKeySize == (CK_ULONG)RSA_MAX_SIZE,
               "CKM_RSA_PKCS sizes are 1024 and RSA_MAX_SIZE");

    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
            TMPL_CNT(pubTmpl), privTmpl, TMPL_CNT(privTmpl), &pub, &priv);
    CHECK_RV(rv, "modulus below the minimum", CKR_ATTRIBUTE_VALUE_INVALID);

    bits = 2048;
    rv = funcList->C_GenerateKeyPair(session, &mech, expTmpl,
            TMPL_CNT(expTmpl), privTmpl, TMPL_CNT(privTmpl), &pub, &priv);
    CHECK_RV(rv, "exponent wider than a long", CKR_TEMPLATE_INCONSISTENT);
    expTmpl[3].pValue = evenExp;
    expTmpl[3].ulValueLen = sizeof(evenExp);
    rv = funcList->C_GenerateKeyPair(session, &mech, expTmpl,
            TMPL_CNT(expTmpl), privTmpl, TMPL_CNT(privTmpl), &pub, &priv);
    CHECK_RV(rv, "even exponent", CKR_TEMPLATE_INCONSISTENT);
    expTmpl[3].pValue = zeroExp;
    expTmpl[3].ulValueLen = sizeof(zeroExp);
    rv = funcList->C_GenerateKeyPair(session, &mech, expTmpl,
            TMPL_CNT(expTmpl), privTmpl, TMPL_CNT(privTmpl), &pub, &priv);
    CHECK_RV(rv, "zero exponent", CKR_TEMPLATE_INCONSISTENT);
    expTmpl[3].ulValueLen = CK_UNAVAILABLE_INFORMATION;
    rv = funcList->C_GenerateKeyPair(session, &mech, expTmpl,
            TMPL_CNT(expTmpl), privTmpl, TMPL_CNT(privTmpl), &pub, &priv);
    CHECK_RV(rv, "exponent of unavailable length", CKR_ATTRIBUTE_VALUE_INVALID);
}
#endif

static void test_generic_secret_len(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };
    CK_ULONG len = 32;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_TOKEN,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_VALUE_LEN, &len,         sizeof(len)         },
    };

    printf("\n--- generic secret length ---\n");

    rv = funcList->C_GenerateKey(session, &mech, tmpl, TMPL_CNT(tmpl), &key);
    CHECK_RV(rv, "32 bytes (control)", CKR_OK);
    if (rv == CKR_OK)
        funcList->C_DestroyObject(session, key);
    len = 0x100000;
    rv = funcList->C_GenerateKey(session, &mech, tmpl, TMPL_CNT(tmpl), &key);
    CHECK_RV(rv, "1 MiB", CKR_ATTRIBUTE_VALUE_INVALID);
}

#ifdef WOLFPKCS11_HKDF
static void test_hkdf_len(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_HKDF_PARAMS params;
    CK_MECHANISM mech = { CKM_HKDF_DERIVE, &params, sizeof(params) };
    CK_MECHANISM_INFO info;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG len = 32;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_TOKEN,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_VALUE_LEN, &len,         sizeof(len)         },
    };

    printf("\n--- HKDF output length ---\n");

    XMEMSET(&params, 0, sizeof(params));
    params.bExtract = CK_TRUE;
    params.bExpand = CK_TRUE;
    params.prfHashMechanism = CKM_SHA256;
    params.ulSaltType = CKF_HKDF_SALT_NULL;

    rv = funcList->C_GetMechanismInfo(session_slot(session), CKM_HKDF_DERIVE,
                                      &info);
    CHECK_RV(rv, "C_GetMechanismInfo", CKR_OK);
    if (rv != CKR_OK || create_generic_key(session, &base) != CKR_OK)
        return;

    rv = funcList->C_DeriveKey(session, &mech, base, tmpl, TMPL_CNT(tmpl),
                               &key);
    CHECK_RV(rv, "32 bytes (control)", CKR_OK);
    if (rv == CKR_OK)
        funcList->C_DestroyObject(session, key);
    len = info.ulMaxKeySize;
    rv = funcList->C_DeriveKey(session, &mech, base, tmpl, TMPL_CNT(tmpl),
                               &key);
    CHECK_RV(rv, "advertised maximum", CKR_OK);
    if (rv == CKR_OK)
        funcList->C_DestroyObject(session, key);
    len = info.ulMaxKeySize + 1;
    rv = funcList->C_DeriveKey(session, &mech, base, tmpl, TMPL_CNT(tmpl),
                               &key);
    CHECK_RV(rv, "above the advertised maximum", CKR_ATTRIBUTE_VALUE_INVALID);
    len = 32;
    params.ulSaltType = CKF_HKDF_SALT_KEY;
    params.hSaltKey = BAD_HANDLE;
    rv = funcList->C_DeriveKey(session, &mech, base, tmpl, TMPL_CNT(tmpl),
                               &key);
    CHECK_RV(rv, "unresolved salt key", CKR_MECHANISM_PARAM_INVALID);
    funcList->C_DestroyObject(session, base);
}
#endif

#if defined(HAVE_ECC) && !defined(WOLFPKCS11_TPM)
static void test_ecdh_peer(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_ECDH1_DERIVE_PARAMS params;
    CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    CK_BYTE bigPeer[sizeof(ecc_p256_pub)];
    CK_BYTE offCurve[sizeof(ecc_p256_pub)];
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG len = 32;
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,     &privClass,      sizeof(privClass)       },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)          },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_PRIVATE,   &ckFalse,        sizeof(ckFalse)         },
        { CKA_DERIVE,    &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,     ecc_p256_priv,   sizeof(ecc_p256_priv)   },
    };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_TOKEN,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_VALUE_LEN, &len,         sizeof(len)         },
    };

    printf("\n--- ECDH peer point ---\n");

    rv = funcList->C_CreateObject(session, privTmpl, TMPL_CNT(privTmpl),
                                  &priv);
    CHECK_RV(rv, "create EC private key", CKR_OK);
    if (rv != CKR_OK)
        return;

    XMEMSET(&params, 0, sizeof(params));
    params.kdf = CKD_NULL;
    params.pPublicData = ecc_p256_pub;
    params.ulPublicDataLen = sizeof(ecc_p256_pub);
    rv = funcList->C_DeriveKey(session, &mech, priv, tmpl, TMPL_CNT(tmpl),
                               &key);
    CHECK_RV(rv, "DER peer point (control)", CKR_OK);
    if (rv == CKR_OK)
        funcList->C_DestroyObject(session, key);
    params.ulPublicDataLen = 42;
    rv = funcList->C_DeriveKey(session, &mech, priv, tmpl, TMPL_CNT(tmpl),
                               &key);
    CHECK_RV(rv, "truncated DER peer point", CKR_MECHANISM_PARAM_INVALID);
    XMEMSET(bigPeer, 0xFF, sizeof(bigPeer));
    bigPeer[0] = 0x04;
    bigPeer[1] = 0x41;
    bigPeer[2] = 0x04;
    params.pPublicData = bigPeer;
    params.ulPublicDataLen = sizeof(bigPeer);
    rv = funcList->C_DeriveKey(session, &mech, priv, tmpl, TMPL_CNT(tmpl),
                               &key);
    CHECK_RV(rv, "peer coordinates above p", CKR_MECHANISM_PARAM_INVALID);
    XMEMCPY(offCurve, ecc_p256_pub, sizeof(offCurve));
    offCurve[sizeof(offCurve) - 1] ^= 0x01;
    params.pPublicData = offCurve;
    params.ulPublicDataLen = sizeof(offCurve);
    rv = funcList->C_DeriveKey(session, &mech, priv, tmpl, TMPL_CNT(tmpl),
                               &key);
    CHECK_RV(rv, "peer point off the curve", CKR_MECHANISM_PARAM_INVALID);
    funcList->C_DestroyObject(session, priv);
}
#endif

static void test_object_limit(CK_SESSION_HANDLE session)
{
    CK_RV rv = CKR_OK;
    static CK_OBJECT_HANDLE objs[8192];
    CK_OBJECT_HANDLE copy;
    CK_ULONG cnt = 0;
    CK_ULONG i;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
        { CKA_TOKEN, &ckFalse,   sizeof(ckFalse)   },
    };

    printf("\n--- full object table ---\n");

    while (cnt < TMPL_CNT(objs)) {
        rv = funcList->C_CreateObject(session, tmpl, TMPL_CNT(tmpl),
                                      &objs[cnt]);
        if (rv != CKR_OK)
            break;
        cnt++;
    }
    CHECK_TRUE(cnt > 0, "objects created before the limit");
    if (cnt < TMPL_CNT(objs)) {
        CHECK_RV(rv, "object past the limit", CKR_DEVICE_MEMORY);
        if (cnt > 0) {
            rv = funcList->C_CopyObject(session, objs[0], NULL, 0, &copy);
            CHECK_RV(rv, "copy past the limit", CKR_DEVICE_MEMORY);
        }
    }
    else
        printf("SKIP: object limit above %lu\n", (unsigned long)cnt);
    for (i = 0; i < cnt; i++)
        funcList->C_DestroyObject(session, objs[i]);
}

#ifndef NO_AES
static void test_unwrap(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_ATTRIBUTE inner[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
    };
    CK_ATTRIBUTE kekTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_WRAP,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_UNWRAP,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,    keyBytes,     sizeof(keyBytes)    },
        { CKA_WRAP_TEMPLATE, inner,   sizeof(inner)       },
    };
    CK_ULONG kekCnt = TMPL_CNT(kekTmpl);
    CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;
    CK_BYTE iv[16];
    CK_BYTE blob[48];
    CK_MECHANISM cbcPad = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_ATTRIBUTE ecTmpl[] = {
        { CKA_CLASS,    &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &ecType,    sizeof(ecType)    },
        { CKA_TOKEN,    &ckFalse,   sizeof(ckFalse)   },
        { CKA_PRIVATE,  &ckFalse,   sizeof(ckFalse)   },
    };
#if (defined(HAVE_AES_CBC) && !defined(WOLFPKCS11_NSS)) || \
    defined(HAVE_AES_KEYWRAP)
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
#endif
#ifdef HAVE_AES_KEYWRAP
    CK_MECHANISM keyWrap = { CKM_AES_KEY_WRAP, NULL, 0 };
#endif
#if defined(HAVE_AES_CBC) && !defined(WOLFPKCS11_NSS)
    CK_ULONG encLen = sizeof(blob);
    static CK_BYTE bigClear[4100];
    static CK_BYTE bigBlob[4100 + 16];
    CK_ULONG bigLen;
    CK_ATTRIBUTE genTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
#endif

    printf("\n--- attribute-array templates and unwrap ---\n");
    XMEMSET(iv, 0, sizeof(iv));
    XMEMSET(blob, 0x5A, sizeof(blob));

    create_expect(session, kekTmpl, kekCnt, CKR_TEMPLATE_INCONSISTENT,
                  "CKA_WRAP_TEMPLATE");
    kekTmpl[kekCnt - 1].type = CKA_UNWRAP_TEMPLATE;
    create_expect(session, kekTmpl, kekCnt, CKR_TEMPLATE_INCONSISTENT,
                  "CKA_UNWRAP_TEMPLATE");
    kekTmpl[kekCnt - 1].type = CKA_DERIVE_TEMPLATE;
    create_expect(session, kekTmpl, kekCnt, CKR_TEMPLATE_INCONSISTENT,
                  "CKA_DERIVE_TEMPLATE");

    rv = funcList->C_CreateObject(session, kekTmpl, kekCnt - 1, &kek);
    CHECK_RV(rv, "create KEK", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = funcList->C_SetAttributeValue(session, kek, &kekTmpl[kekCnt - 1], 1);
    CHECK_RV(rv, "set CKA_DERIVE_TEMPLATE", CKR_TEMPLATE_INCONSISTENT);

    rv = funcList->C_UnwrapKey(session, &cbcPad, kek, blob, 32, ecTmpl,
                               TMPL_CNT(ecTmpl), &key);
    CHECK_RV(rv, "EC private key unwrap", CKR_TEMPLATE_INCONSISTENT);
#if defined(HAVE_AES_CBC) && !defined(WOLFPKCS11_NSS)
    rv = funcList->C_EncryptInit(session, &cbcPad, kek);
    if (rv == CKR_OK)
        rv = funcList->C_Encrypt(session, keyBytes, 20, blob, &encLen);
    CHECK_RV(rv, "CBC-PAD encrypt a 20-byte value", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &cbcPad, kek, blob, encLen,
                                   aesTmpl, TMPL_CNT(aesTmpl), &key);
        CHECK_RV(rv, "20-byte AES key unwrap", CKR_WRAPPED_KEY_INVALID);
    }
    bigLen = sizeof(bigBlob);
    rv = funcList->C_EncryptInit(session, &cbcPad, kek);
    if (rv == CKR_OK)
        rv = funcList->C_Encrypt(session, bigClear, sizeof(bigClear), bigBlob,
                                 &bigLen);
    CHECK_RV(rv, "CBC-PAD encrypt an oversized secret", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &cbcPad, kek, bigBlob, bigLen,
                                   genTmpl, TMPL_CNT(genTmpl), &key);
        CHECK_RV(rv, "oversized secret unwrap", CKR_WRAPPED_KEY_LEN_RANGE);
    }
    XMEMSET(blob, 0x5A, sizeof(blob));
#endif
#ifdef HAVE_AES_KEYWRAP
    rv = funcList->C_UnwrapKey(session, &keyWrap, kek, blob, 20, aesTmpl,
                               TMPL_CNT(aesTmpl), &key);
    CHECK_RV(rv, "20-byte AES key wrap blob", CKR_WRAPPED_KEY_LEN_RANGE);
    rv = funcList->C_UnwrapKey(session, &keyWrap, kek, blob, 24, aesTmpl,
                               TMPL_CNT(aesTmpl), &key);
    CHECK_RV(rv, "24-byte corrupt blob (control)", CKR_WRAPPED_KEY_INVALID);
#endif
    funcList->C_DestroyObject(session, kek);
}
#endif

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
    if (rv != CKR_OK)
        goto out;

    test_key_handles(session);
#ifndef NO_AES
    test_fixed_size_attrs(session);
#endif
    test_get_attr_short_buffer(session);
#ifndef NO_RSA
    test_rsa_public_attrs(session);
#endif
#ifdef HAVE_ECC
    test_ec_public_attrs(session);
    test_ec_params(session);
#endif
    test_create_object(session);
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    test_rsa_keygen(session);
#endif
    test_generic_secret_len(session);
#ifdef WOLFPKCS11_HKDF
    test_hkdf_len(session);
#endif
#if defined(HAVE_ECC) && !defined(WOLFPKCS11_TPM)
    test_ecdh_peer(session);
#endif
#ifndef NO_AES
    test_unwrap(session);
#endif
    test_object_limit(session);

out:
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
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

    printf("=== wolfPKCS11 object and template return code test ===\n");
    run_test();
    return pkcs11_test_summary();
}
