/* object_create_getattr_test.c
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
 * Objects created with C_CreateObject carry the attributes PKCS#11 requires,
 * and attributes read back with C_GetAttributeValue follow the PKCS#11
 * length and error conventions.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/object_create_getattr_test"

static CK_BBOOL ckFalse = CK_FALSE;
static const byte certValue[] = { 0x30, 0x82, 0x01, 0x00 };
static const byte certSubject[] = { 0x30, 0x00 };
static const char certUrl[] = "http://example.com/cert.der";
#ifdef HAVE_ECC
static const byte keySubject[] = {
    0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x04, 0x74, 0x65, 0x73, 0x74
};
static const byte keySerial[] = { 0x02, 0x01, 0x01 };
#endif
static const byte dataValue[] = "object-create-data";
static const byte dataLabel[] = "object-create-data-label";
static const byte secretValue[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static void destroy_obj(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* obj)
{
    if (*obj != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, *obj);
        *obj = CK_INVALID_HANDLE;
    }
}

/* Create an object, expecting rv, and destroy anything that was created. */
static void expect_create(CK_SESSION_HANDLE session, CK_ATTRIBUTE* tmpl,
                          CK_ULONG cnt, CK_RV expected, const char* name)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;

    rv = funcList->C_CreateObject(session, tmpl, cnt, &obj);
    CHECK_RV(rv, name, expected);
    if (rv == CKR_OK)
        destroy_obj(session, &obj);
}

/* A certificate object needs its encoding. */
static void test_cert_requires_value(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_CERTIFICATE_TYPE attrCertType = CKC_X_509_ATTR_CERT;
    CK_ATTRIBUTE noValue[] = {
        { CKA_CLASS,            &certClass,          sizeof(certClass)   },
        { CKA_CERTIFICATE_TYPE, &certType,           sizeof(certType)    },
        { CKA_TOKEN,            &ckFalse,            sizeof(ckFalse)     },
        { CKA_SUBJECT,          (void*)certSubject,  sizeof(certSubject) },
    };
    CK_ATTRIBUTE attrCertNoValue[] = {
        { CKA_CLASS,            &certClass,          sizeof(certClass)    },
        { CKA_CERTIFICATE_TYPE, &attrCertType,       sizeof(attrCertType) },
        { CKA_TOKEN,            &ckFalse,            sizeof(ckFalse)      },
    };
    CK_ATTRIBUTE emptyValue[] = {
        { CKA_CLASS,            &certClass,          sizeof(certClass)   },
        { CKA_CERTIFICATE_TYPE, &certType,           sizeof(certType)    },
        { CKA_TOKEN,            &ckFalse,            sizeof(ckFalse)     },
        { CKA_SUBJECT,          (void*)certSubject,  sizeof(certSubject) },
        { CKA_VALUE,            (void*)certValue,    0                   },
    };
    CK_ATTRIBUTE urlOnly[] = {
        { CKA_CLASS,            &certClass,          sizeof(certClass)   },
        { CKA_CERTIFICATE_TYPE, &certType,           sizeof(certType)    },
        { CKA_TOKEN,            &ckFalse,            sizeof(ckFalse)     },
        { CKA_SUBJECT,          (void*)certSubject,  sizeof(certSubject) },
        { CKA_VALUE,            (void*)certValue,    0                   },
        { CKA_URL,              (void*)certUrl,      sizeof(certUrl) - 1 },
    };
    CK_ATTRIBUTE complete[] = {
        { CKA_CLASS,            &certClass,          sizeof(certClass)   },
        { CKA_CERTIFICATE_TYPE, &certType,           sizeof(certType)    },
        { CKA_TOKEN,            &ckFalse,            sizeof(ckFalse)     },
        { CKA_SUBJECT,          (void*)certSubject,  sizeof(certSubject) },
        { CKA_VALUE,            (void*)certValue,    sizeof(certValue)   },
    };

    expect_create(session, noValue, sizeof(noValue) / sizeof(*noValue),
                  CKR_TEMPLATE_INCOMPLETE, "certificate without CKA_VALUE");
    expect_create(session, attrCertNoValue,
                  sizeof(attrCertNoValue) / sizeof(*attrCertNoValue),
                  CKR_TEMPLATE_INCOMPLETE,
                  "attribute certificate without CKA_VALUE");
    expect_create(session, emptyValue,
                  sizeof(emptyValue) / sizeof(*emptyValue),
                  CKR_ATTRIBUTE_VALUE_INVALID,
                  "certificate with empty CKA_VALUE");
    expect_create(session, urlOnly, sizeof(urlOnly) / sizeof(*urlOnly),
                  CKR_ATTRIBUTE_VALUE_INVALID,
                  "certificate located only by CKA_URL");
    expect_create(session, complete, sizeof(complete) / sizeof(*complete),
                  CKR_OK, "complete certificate");
}

/* A secret key object needs its key value. */
static void test_secret_key_requires_value(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    CK_ULONG valueLen = sizeof(secretValue);
    CK_ATTRIBUTE noValue[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_TOKEN,     &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ATTRIBUTE lenOnly[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_TOKEN,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_VALUE_LEN, &valueLen,    sizeof(valueLen)    },
    };
    CK_ATTRIBUTE emptyValue[] = {
        { CKA_CLASS,     &secretClass,        sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType,        sizeof(genericType) },
        { CKA_TOKEN,     &ckFalse,            sizeof(ckFalse)     },
        { CKA_VALUE,     (void*)secretValue,  0                   },
    };
    CK_ATTRIBUTE complete[] = {
        { CKA_CLASS,     &secretClass,        sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType,        sizeof(genericType) },
        { CKA_TOKEN,     &ckFalse,            sizeof(ckFalse)     },
        { CKA_VALUE,     (void*)secretValue,  sizeof(secretValue) },
    };
#ifndef NO_AES
    CK_KEY_TYPE aesType = CKK_AES;
    CK_ATTRIBUTE aesNoValue[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,     &ckFalse,     sizeof(ckFalse)     },
    };
#endif

    expect_create(session, noValue, sizeof(noValue) / sizeof(*noValue),
                  CKR_TEMPLATE_INCOMPLETE, "secret key without CKA_VALUE");
    expect_create(session, lenOnly, sizeof(lenOnly) / sizeof(*lenOnly),
                  CKR_TEMPLATE_INCOMPLETE,
                  "secret key with only CKA_VALUE_LEN");
    expect_create(session, emptyValue,
                  sizeof(emptyValue) / sizeof(*emptyValue),
                  CKR_ATTRIBUTE_VALUE_INVALID,
                  "secret key with empty CKA_VALUE");
#ifndef NO_AES
    expect_create(session, aesNoValue,
                  sizeof(aesNoValue) / sizeof(*aesNoValue),
                  CKR_TEMPLATE_INCOMPLETE, "AES key without CKA_VALUE");
#endif
    expect_create(session, complete, sizeof(complete) / sizeof(*complete),
                  CKR_OK, "complete secret key");
}

/* An attribute count beyond what the library can index is rejected. */
static void test_create_count_range(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &secretClass,        sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType,        sizeof(genericType) },
        { CKA_TOKEN,     &ckFalse,            sizeof(ckFalse)     },
        { CKA_VALUE,     (void*)secretValue,  sizeof(secretValue) },
    };

    expect_create(session, tmpl, (CK_ULONG)INT_MAX + 1, CKR_ARGUMENTS_BAD,
                  "create with oversized attribute count");
}

#if !defined(NO_RSA) || defined(HAVE_ECC)
/* A secret key object needs a secret key type, for session and token objects,
 * and nothing is stored when it does not. */
static void test_key_type_matches_class(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_BBOOL onToken = CK_FALSE;
    CK_OBJECT_HANDLE found[2];
    CK_ULONG foundCnt = 0;
    int i;
#ifndef NO_RSA
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_ATTRIBUTE rsaSecret[] = {
        { CKA_CLASS,           &secretClass,     sizeof(secretClass)      },
        { CKA_KEY_TYPE,        &rsaType,         sizeof(rsaType)          },
        { CKA_TOKEN,           &onToken,         sizeof(onToken)          },
        { CKA_PRIVATE,         &ckFalse,         sizeof(ckFalse)          },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };
    CK_ATTRIBUTE rsaFind[] = {
        { CKA_CLASS,           &secretClass,     sizeof(secretClass)      },
        { CKA_KEY_TYPE,        &rsaType,         sizeof(rsaType)          },
    };
#endif
#ifdef HAVE_ECC
    CK_KEY_TYPE ecType = CKK_EC;
    CK_ATTRIBUTE ecSecret[] = {
        { CKA_CLASS,     &secretClass,    sizeof(secretClass)     },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)          },
        { CKA_TOKEN,     &onToken,        sizeof(onToken)         },
        { CKA_PRIVATE,   &ckFalse,        sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_EC_POINT,  ecc_p256_pub,    sizeof(ecc_p256_pub)    },
    };
#endif

    for (i = 0; i < 2; i++) {
        onToken = (i == 0) ? CK_FALSE : CK_TRUE;
#ifndef NO_RSA
        expect_create(session, rsaSecret,
                      sizeof(rsaSecret) / sizeof(*rsaSecret),
                      CKR_TEMPLATE_INCONSISTENT, "RSA key type as secret key");
#endif
#ifdef HAVE_ECC
        expect_create(session, ecSecret, sizeof(ecSecret) / sizeof(*ecSecret),
                      CKR_TEMPLATE_INCONSISTENT, "EC key type as secret key");
#endif
    }

#ifndef NO_RSA
    rv = funcList->C_FindObjectsInit(session, rsaFind,
                                     sizeof(rsaFind) / sizeof(*rsaFind));
    CHECK_RV(rv, "find inconsistent objects init", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, found, 2, &foundCnt);
        CHECK_TRUE(rv == CKR_OK && foundCnt == 0,
                   "no inconsistent object stored");
        funcList->C_FindObjectsFinal(session);
    }
#else
    (void)rv;
    (void)found;
    (void)foundCnt;
#endif
}
#endif

#if !defined(NO_RSA) || defined(HAVE_ECC)
#define MAX_TMPL 16

/* The full template creates the object, and leaving out any one of the
 * required attributes is reported as an incomplete template. */
static void expect_required(CK_SESSION_HANDLE session, CK_ATTRIBUTE* tmpl,
                            CK_ULONG cnt, const CK_ATTRIBUTE_TYPE* required,
                            CK_ULONG reqCnt, const char* name)
{
    CK_ATTRIBUTE partial[MAX_TMPL];
    CK_ULONG i;
    CK_ULONG j;
    CK_ULONG n;
    char msg[96];

    if (cnt > MAX_TMPL) {
        CHECK_TRUE(0, "template fits");
        return;
    }
    for (i = 0; i < reqCnt; i++) {
        n = 0;
        for (j = 0; j < cnt; j++) {
            if (tmpl[j].type != required[i])
                partial[n++] = tmpl[j];
        }
        snprintf(msg, sizeof(msg), "%s without attribute 0x%lx", name,
                 (unsigned long)required[i]);
        expect_create(session, partial, n, CKR_TEMPLATE_INCOMPLETE, msg);
    }
    snprintf(msg, sizeof(msg), "complete %s", name);
    expect_create(session, tmpl, cnt, CKR_OK, msg);
}
#endif

#ifndef NO_RSA
/* An RSA key object needs the components that define the key. */
static void test_rsa_key_requires_material(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,            &pubClass,         sizeof(pubClass)          },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_TOKEN,            &ckFalse,          sizeof(ckFalse)           },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,            &privClass,        sizeof(privClass)         },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_TOKEN,            &ckFalse,          sizeof(ckFalse)           },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
    };
    CK_ATTRIBUTE primesTmpl[] = {
        { CKA_CLASS,            &privClass,        sizeof(privClass)         },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_TOKEN,            &ckFalse,          sizeof(ckFalse)           },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
    };
    static const CK_ATTRIBUTE_TYPE pubReq[] = {
        CKA_MODULUS, CKA_PUBLIC_EXPONENT
    };
    static const CK_ATTRIBUTE_TYPE privReq[] = {
        CKA_MODULUS, CKA_PRIVATE_EXPONENT
    };
    static const CK_ATTRIBUTE_TYPE primesReq[] = {
        CKA_PRIME_1, CKA_PRIME_2, CKA_PRIVATE_EXPONENT
    };

    expect_required(session, pubTmpl, sizeof(pubTmpl) / sizeof(*pubTmpl),
                    pubReq, sizeof(pubReq) / sizeof(*pubReq),
                    "RSA public key");
    expect_required(session, privTmpl, sizeof(privTmpl) / sizeof(*privTmpl),
                    privReq, sizeof(privReq) / sizeof(*privReq),
                    "RSA private key");
    expect_required(session, primesTmpl,
                    sizeof(primesTmpl) / sizeof(*primesTmpl), primesReq,
                    sizeof(primesReq) / sizeof(*primesReq),
                    "RSA private key from primes");
}
#endif

#ifdef HAVE_ECC
/* An EC key object needs its curve and its point or private value. */
static void test_ec_key_requires_material(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,     &pubClass,       sizeof(pubClass)        },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)          },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_EC_POINT,  ecc_p256_pub,    sizeof(ecc_p256_pub)    },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,     &privClass,      sizeof(privClass)       },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)          },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_PRIVATE,   &ckFalse,        sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,     ecc_p256_priv,   sizeof(ecc_p256_priv)   },
    };
    static const CK_ATTRIBUTE_TYPE pubReq[] = {
        CKA_EC_PARAMS, CKA_EC_POINT
    };
    static const CK_ATTRIBUTE_TYPE privReq[] = {
        CKA_EC_PARAMS, CKA_VALUE
    };

    expect_required(session, pubTmpl, sizeof(pubTmpl) / sizeof(*pubTmpl),
                    pubReq, sizeof(pubReq) / sizeof(*pubReq),
                    "EC public key");
    expect_required(session, privTmpl, sizeof(privTmpl) / sizeof(*privTmpl),
                    privReq, sizeof(privReq) / sizeof(*privReq),
                    "EC private key");
}
#endif

/* CKA_VALUE of a data object is optional and defaults to empty. */
static void test_data_object_value_optional(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL onToken = CK_FALSE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    byte buf[32];
    CK_ATTRIBUTE getValue = { CKA_VALUE, buf, sizeof(buf) };
    CK_ATTRIBUTE setValue = { CKA_VALUE, (void*)dataValue,
                              sizeof(dataValue) - 1 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass,       sizeof(dataClass)     },
        { CKA_TOKEN,   &onToken,         sizeof(onToken)       },
        { CKA_PRIVATE, &ckFalse,         sizeof(ckFalse)       },
        { CKA_LABEL,   (void*)dataLabel, sizeof(dataLabel) - 1 },
    };
    int i;

    for (i = 0; i < 2; i++) {
        onToken = (i == 0) ? CK_FALSE : CK_TRUE;
        rv = funcList->C_CreateObject(session, tmpl,
                                      sizeof(tmpl) / sizeof(*tmpl), &obj);
        CHECK_RV(rv, "create data object without CKA_VALUE", CKR_OK);
        if (rv != CKR_OK)
            continue;

        getValue.ulValueLen = sizeof(buf);
        rv = funcList->C_GetAttributeValue(session, obj, &getValue, 1);
        CHECK_TRUE(rv == CKR_OK && getValue.ulValueLen == 0,
                   "omitted data object value reads as empty");

        rv = funcList->C_SetAttributeValue(session, obj, &setValue, 1);
        CHECK_RV(rv, "set data object value later", CKR_OK);
        getValue.ulValueLen = sizeof(buf);
        rv = funcList->C_GetAttributeValue(session, obj, &getValue, 1);
        CHECK_TRUE(rv == CKR_OK &&
                   getValue.ulValueLen == sizeof(dataValue) - 1 &&
                   XMEMCMP(buf, dataValue, sizeof(dataValue) - 1) == 0,
                   "data object value set after creation");

        destroy_obj(session, &obj);
    }
}

#if defined(HAVE_ECC) || defined(WOLFPKCS11_MLDSA) || defined(WOLFPKCS11_MLKEM)
/* An attribute the object cannot provide is reported as an error, with the
 * length set to CK_UNAVAILABLE_INFORMATION, for size queries and reads. */
static void expect_unavailable(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                               CK_ATTRIBUTE_TYPE type, const char* name)
{
    CK_RV rv;
    byte buf[64];
    CK_ATTRIBUTE query = { type, NULL, 0 };
    CK_ATTRIBUTE read = { type, buf, sizeof(buf) };
    char msg[96];

    rv = funcList->C_GetAttributeValue(session, obj, &query, 1);
    snprintf(msg, sizeof(msg), "%s size query fails", name);
    CHECK_TRUE(rv != CKR_OK &&
               query.ulValueLen == CK_UNAVAILABLE_INFORMATION, msg);
    rv = funcList->C_GetAttributeValue(session, obj, &read, 1);
    snprintf(msg, sizeof(msg), "%s read fails", name);
    CHECK_TRUE(rv != CKR_OK &&
               read.ulValueLen == CK_UNAVAILABLE_INFORMATION, msg);
}
#endif

#if defined(WOLFPKCS11_MLDSA) || defined(WOLFPKCS11_MLKEM)
/* Generate a parameter-set based key pair as public session objects. */
static CK_RV gen_pq_key_pair(CK_SESSION_HANDLE session, CK_MECHANISM_TYPE type,
                             CK_ULONG paramSet, CK_OBJECT_HANDLE* pub,
                             CK_OBJECT_HANDLE* priv)
{
    CK_MECHANISM mech = { type, NULL, 0 };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
        { CKA_TOKEN,         &ckFalse,  sizeof(ckFalse)  },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,         &ckFalse,  sizeof(ckFalse)  },
        { CKA_PRIVATE,       &ckFalse,  sizeof(ckFalse)  },
    };

    return funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
        sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
        sizeof(privTmpl) / sizeof(*privTmpl), pub, priv);
}

/* Create a public key object carrying only its parameter set. */
static CK_RV create_pq_params_only(CK_SESSION_HANDLE session,
                                   CK_KEY_TYPE keyType, CK_ULONG paramSet,
                                   CK_OBJECT_HANDLE* obj)
{
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,         &pubClass, sizeof(pubClass) },
        { CKA_KEY_TYPE,      &keyType,  sizeof(keyType)  },
        { CKA_TOKEN,         &ckFalse,  sizeof(ckFalse)  },
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
    };

    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), obj);
}

static void check_pq_unavailable(CK_SESSION_HANDLE session,
                                 CK_MECHANISM_TYPE genMech,
                                 CK_KEY_TYPE keyType, CK_ULONG paramSet,
                                 const char* name)
{
    CK_RV rv;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE noPub = CK_INVALID_HANDLE;
    char msg[96];

    rv = gen_pq_key_pair(session, genMech, paramSet, &pub, &priv);
    snprintf(msg, sizeof(msg), "%s generate key pair", name);
    CHECK_RV(rv, msg, CKR_OK);
    if (rv == CKR_OK) {
        snprintf(msg, sizeof(msg), "%s private key CKA_SEED", name);
        expect_unavailable(session, priv, CKA_SEED, msg);
    }

    rv = create_pq_params_only(session, keyType, paramSet, &noPub);
    snprintf(msg, sizeof(msg), "%s public key without value", name);
    CHECK_RV(rv, msg, CKR_OK);
    if (rv == CKR_OK) {
        snprintf(msg, sizeof(msg), "%s missing public CKA_VALUE", name);
        expect_unavailable(session, noPub, CKA_VALUE, msg);
    }

    destroy_obj(session, &noPub);
    destroy_obj(session, &priv);
    destroy_obj(session, &pub);
}
#endif

static void test_unavailable_attr_is_error(CK_SESSION_HANDLE session)
{
#ifdef HAVE_ECC
    CK_RV rv;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_OBJECT_HANDLE ecPriv = CK_INVALID_HANDLE;
    CK_ATTRIBUTE ecTmpl[] = {
        { CKA_CLASS,     &privClass,      sizeof(privClass)       },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)          },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_PRIVATE,   &ckFalse,        sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,     ecc_p256_priv,   sizeof(ecc_p256_priv)   },
    };

    rv = funcList->C_CreateObject(session, ecTmpl,
                                  sizeof(ecTmpl) / sizeof(*ecTmpl), &ecPriv);
    CHECK_RV(rv, "create EC private key without point", CKR_OK);
    if (rv == CKR_OK)
        expect_unavailable(session, ecPriv, CKA_EC_POINT, "EC point");
    destroy_obj(session, &ecPriv);
#endif
#ifdef WOLFPKCS11_MLDSA
    check_pq_unavailable(session, CKM_ML_DSA_KEY_PAIR_GEN, CKK_ML_DSA,
                         CKP_ML_DSA_44, "ML-DSA");
#endif
#ifdef WOLFPKCS11_MLKEM
    check_pq_unavailable(session, CKM_ML_KEM_KEY_PAIR_GEN, CKK_ML_KEM,
                         CKP_ML_KEM_512, "ML-KEM");
#endif
    (void)session;
}

/* CKA_CERTIFICATE_CATEGORY reads back as supplied, and defaults to 0. */
static void test_cert_category_roundtrip(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_ULONG category = 2;
    CK_ULONG got;
    CK_OBJECT_HANDLE cert = CK_INVALID_HANDLE;
    CK_ATTRIBUTE get = { CKA_CERTIFICATE_CATEGORY, NULL, 0 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,                &certClass,         sizeof(certClass)   },
        { CKA_CERTIFICATE_TYPE,     &certType,          sizeof(certType)    },
        { CKA_TOKEN,                &ckFalse,           sizeof(ckFalse)     },
        { CKA_SUBJECT,              (void*)certSubject, sizeof(certSubject) },
        { CKA_VALUE,                (void*)certValue,   sizeof(certValue)   },
        { CKA_CERTIFICATE_CATEGORY, &category,          sizeof(category)    },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);
    int i;

    for (i = 0; i < 2; i++) {
        rv = funcList->C_CreateObject(session, tmpl, cnt - (CK_ULONG)i, &cert);
        CHECK_RV(rv, "create certificate", CKR_OK);
        if (rv != CKR_OK)
            continue;

        get.pValue = NULL;
        get.ulValueLen = 0;
        rv = funcList->C_GetAttributeValue(session, cert, &get, 1);
        CHECK_TRUE(rv == CKR_OK && get.ulValueLen == sizeof(CK_ULONG),
                   "certificate category size");
        got = (CK_ULONG)-1;
        get.pValue = &got;
        get.ulValueLen = sizeof(got);
        rv = funcList->C_GetAttributeValue(session, cert, &get, 1);
        CHECK_TRUE(rv == CKR_OK && get.ulValueLen == sizeof(got) &&
                   got == ((i == 0) ? category : 0),
                   (i == 0) ? "certificate category reads back" :
                              "certificate category defaults to 0");
        destroy_obj(session, &cert);
    }
}

#ifdef HAVE_ECC
/* CKA_SUBJECT on a public or private key reads back as supplied, and the
 * certificate-only CKA_ISSUER and CKA_SERIAL_NUMBER are not accepted. */
static void test_key_subject_roundtrip(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte buf[32];
    CK_ATTRIBUTE get = { CKA_SUBJECT, buf, sizeof(buf) };
    CK_ATTRIBUTE issuer = { CKA_ISSUER, (void*)keySubject,
                            sizeof(keySubject) };
    CK_ATTRIBUTE serial = { CKA_SERIAL_NUMBER, (void*)keySerial,
                            sizeof(keySerial) };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,     &pubClass,          sizeof(pubClass)        },
        { CKA_KEY_TYPE,  &ecType,            sizeof(ecType)          },
        { CKA_TOKEN,     &ckFalse,           sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params,    sizeof(ecc_p256_params) },
        { CKA_EC_POINT,  ecc_p256_pub,       sizeof(ecc_p256_pub)    },
        { CKA_SUBJECT,   (void*)keySubject,  sizeof(keySubject)      },
        { CKA_ISSUER,    (void*)keySubject,  sizeof(keySubject)      },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,     &privClass,         sizeof(privClass)       },
        { CKA_KEY_TYPE,  &ecType,            sizeof(ecType)          },
        { CKA_TOKEN,     &ckFalse,           sizeof(ckFalse)         },
        { CKA_PRIVATE,   &ckFalse,           sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params,    sizeof(ecc_p256_params) },
        { CKA_VALUE,     ecc_p256_priv,      sizeof(ecc_p256_priv)   },
        { CKA_SUBJECT,   (void*)keySubject,  sizeof(keySubject)      },
        { CKA_SERIAL_NUMBER, (void*)keySerial, sizeof(keySerial)     },
    };
    CK_ULONG pubCnt = sizeof(pubTmpl) / sizeof(*pubTmpl);
    CK_ULONG privCnt = sizeof(privTmpl) / sizeof(*privTmpl);

    rv = funcList->C_CreateObject(session, pubTmpl, pubCnt, &key);
    CHECK_TRUE(rv != CKR_OK, "public key with CKA_ISSUER rejected");
    destroy_obj(session, &key);
    rv = funcList->C_CreateObject(session, privTmpl, privCnt, &key);
    CHECK_TRUE(rv != CKR_OK, "private key with CKA_SERIAL_NUMBER rejected");
    destroy_obj(session, &key);

    rv = funcList->C_CreateObject(session, pubTmpl, pubCnt - 1, &key);
    CHECK_RV(rv, "create public key with subject", CKR_OK);
    if (rv == CKR_OK) {
        get.ulValueLen = sizeof(buf);
        rv = funcList->C_GetAttributeValue(session, key, &get, 1);
        CHECK_TRUE(rv == CKR_OK && get.ulValueLen == sizeof(keySubject) &&
                   XMEMCMP(buf, keySubject, sizeof(keySubject)) == 0,
                   "public key subject reads back");
        rv = funcList->C_SetAttributeValue(session, key, &issuer, 1);
        CHECK_TRUE(rv != CKR_OK, "set CKA_ISSUER on public key rejected");
    }
    destroy_obj(session, &key);

    rv = funcList->C_CreateObject(session, privTmpl, privCnt - 1, &key);
    CHECK_RV(rv, "create private key with subject", CKR_OK);
    if (rv == CKR_OK) {
        get.ulValueLen = sizeof(buf);
        rv = funcList->C_GetAttributeValue(session, key, &get, 1);
        CHECK_TRUE(rv == CKR_OK && get.ulValueLen == sizeof(keySubject) &&
                   XMEMCMP(buf, keySubject, sizeof(keySubject)) == 0,
                   "private key subject reads back");
        rv = funcList->C_SetAttributeValue(session, key, &serial, 1);
        CHECK_TRUE(rv != CKR_OK,
                   "set CKA_SERIAL_NUMBER on private key rejected");
    }
    destroy_obj(session, &key);
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
    if (rv == CKR_OK) {
        test_cert_requires_value(session);
        test_secret_key_requires_value(session);
        test_create_count_range(session);
        test_data_object_value_optional(session);
        test_unavailable_attr_is_error(session);
        test_cert_category_roundtrip(session);
#ifdef HAVE_ECC
        test_key_subject_roundtrip(session);
#endif
#if !defined(NO_RSA) || defined(HAVE_ECC)
        test_key_type_matches_class(session);
#endif
#ifndef NO_RSA
        test_rsa_key_requires_material(session);
#endif
#ifdef HAVE_ECC
        test_ec_key_requires_material(session);
#endif
    }

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

    printf("=== wolfPKCS11 object create and get attribute test ===\n");
    run_test();
    return pkcs11_test_summary();
}
