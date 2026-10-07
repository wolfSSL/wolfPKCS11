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
