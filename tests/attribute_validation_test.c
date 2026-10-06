/* attribute_validation_test.c
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
 * Attribute templates supplied when creating or updating objects are
 * validated, and defaulted attributes behave as PKCS#11 specifies.
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
#include <wolfssl/wolfcrypt/memory.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/attribute_validation_test"

#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_DEBUG_MEMORY)
#define ATTR_TEST_ALLOC_HOOK
/* Allocation of exactly this size fails while armed. */
#define FAIL_ALLOC_SIZE 97
static int failAllocArmed = 0;

static void* test_malloc(size_t n)
{
    if (failAllocArmed && n == FAIL_ALLOC_SIZE)
        return NULL;
    return malloc(n);
}

static void test_free(void* p)
{
    free(p);
}

static void* test_realloc(void* p, size_t n)
{
    if (failAllocArmed && n == FAIL_ALLOC_SIZE)
        return NULL;
    return realloc(p, n);
}
#endif

static CK_OBJECT_CLASS dataClass = CKO_DATA;
static CK_BBOOL ckTrue  = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static const byte dataValue[] = "attribute-validation";
static const byte dataLabel[] = "attribute-validation-label";
static const byte newLabel[]  = "replaced";

/* Check that the object's CKA_LABEL is exactly the expected bytes. */
static void expect_label(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                         const byte* expect, CK_ULONG expectLen,
                         const char* name)
{
    CK_RV rv;
    byte buf[64];
    CK_ATTRIBUTE attr = { CKA_LABEL, buf, sizeof(buf) };

    rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    CHECK_TRUE(rv == CKR_OK && attr.ulValueLen == expectLen &&
               XMEMCMP(buf, expect, expectLen) == 0, name);
}

/* Check that a boolean attribute of the object has the expected value. */
static void expect_bool(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                        CK_ATTRIBUTE_TYPE type, CK_BBOOL expect,
                        const char* name)
{
    CK_RV rv;
    CK_BBOOL val = (CK_BBOOL)!expect;
    CK_ATTRIBUTE attr = { type, &val, sizeof(val) };

    rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    CHECK_TRUE(rv == CKR_OK && val == expect, name);
}

static void destroy_obj(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* obj)
{
    if (*obj != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, *obj);
        *obj = CK_INVALID_HANDLE;
    }
}

/* Create a public, modifiable session data object. */
static CK_RV create_data_object(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE* obj)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass,        sizeof(dataClass)     },
        { CKA_TOKEN,   &ckFalse,          sizeof(ckFalse)       },
        { CKA_PRIVATE, &ckFalse,          sizeof(ckFalse)       },
        { CKA_LABEL,   (void*)dataLabel,  sizeof(dataLabel) - 1 },
        { CKA_VALUE,   (void*)dataValue,  sizeof(dataValue) - 1 },
    };

    *obj = CK_INVALID_HANDLE;
    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), obj);
}

/* CKA_TOKEN is validated as a CK_BBOOL like every other boolean attribute. */
static void test_token_attr_is_bool(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE bad = CK_INVALID_HANDLE;
    CK_BBOOL badBool = 5;
    byte wide[2] = { 0, 0 };
    CK_ATTRIBUTE nullTmpl[] = { { CKA_TOKEN, NULL, sizeof(CK_BBOOL) } };
    CK_ATTRIBUTE wideTmpl[] = { { CKA_TOKEN, wide, sizeof(wide) } };
    CK_ATTRIBUTE badTmpl[]  = { { CKA_TOKEN, &badBool, sizeof(badBool) } };
    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,   &dataClass,        sizeof(dataClass)     },
        { CKA_TOKEN,   &badBool,          sizeof(badBool)       },
        { CKA_PRIVATE, &ckFalse,          sizeof(ckFalse)       },
        { CKA_VALUE,   (void*)dataValue,  sizeof(dataValue) - 1 },
    };

    rv = create_data_object(session, &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SetAttributeValue(session, obj, nullTmpl, 1);
    CHECK_RV(rv, "set CKA_TOKEN with NULL value", CKR_ATTRIBUTE_VALUE_INVALID);
    rv = funcList->C_SetAttributeValue(session, obj, wideTmpl, 1);
    CHECK_RV(rv, "set CKA_TOKEN with wrong length",
             CKR_ATTRIBUTE_VALUE_INVALID);
    rv = funcList->C_SetAttributeValue(session, obj, badTmpl, 1);
    CHECK_RV(rv, "set CKA_TOKEN with non-boolean value",
             CKR_ATTRIBUTE_VALUE_INVALID);

    rv = funcList->C_CreateObject(session, createTmpl,
                                  sizeof(createTmpl) / sizeof(*createTmpl),
                                  &bad);
    CHECK_RV(rv, "create object with non-boolean CKA_TOKEN",
             CKR_ATTRIBUTE_VALUE_INVALID);
    if (rv == CKR_OK)
        destroy_obj(session, &bad);

    destroy_obj(session, &obj);
}

/* Attribute counts beyond what the library can index are rejected rather
 * than treated as an empty template. */
static void test_set_attr_count_range(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE setTmpl[] = {
        { CKA_LABEL, (void*)newLabel, sizeof(newLabel) - 1 },
    };

    rv = create_data_object(session, &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SetAttributeValue(session, obj, setTmpl,
                                       (CK_ULONG)INT_MAX + 1);
    CHECK_RV(rv, "set attributes with oversized count", CKR_ARGUMENTS_BAD);
    expect_label(session, obj, dataLabel, sizeof(dataLabel) - 1,
                 "label unchanged after oversized count");

    destroy_obj(session, &obj);
}

static void test_get_attr_count_range(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    byte buf[64];
    CK_ATTRIBUTE getTmpl[] = { { CKA_LABEL, buf, sizeof(buf) } };

    rv = create_data_object(session, &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_GetAttributeValue(session, obj, getTmpl,
                                       (CK_ULONG)INT_MAX + 1);
    CHECK_RV(rv, "get attributes with oversized count", CKR_ARGUMENTS_BAD);

    destroy_obj(session, &obj);
}

/* A large result array returns the matching objects rather than none. */
static void test_find_objects_large_max(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &dataClass,       sizeof(dataClass)     },
        { CKA_TOKEN, &ckFalse,         sizeof(ckFalse)       },
        { CKA_LABEL, (void*)dataLabel, sizeof(dataLabel) - 1 },
    };

    rv = create_data_object(session, &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_FindObjectsInit(session, findTmpl,
                                     sizeof(findTmpl) / sizeof(*findTmpl));
    CHECK_RV(rv, "find init", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, &found, (CK_ULONG)INT_MAX + 1,
                                     &count);
        CHECK_RV(rv, "find with large maximum", CKR_OK);
        CHECK_TRUE(count == 1 && found == obj,
                   "find with large maximum returns the object");
        funcList->C_FindObjectsFinal(session);
    }

    destroy_obj(session, &obj);
}

/* CKA_TOKEN, CKA_PRIVATE and CKA_MODIFIABLE only change through
 * C_CopyObject; C_SetAttributeValue may only restate the current value. */
static void test_copy_only_attrs_read_only(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tokenTmpl[]  = { { CKA_TOKEN,      &ckTrue,  1 } };
    CK_ATTRIBUTE privTmpl[]   = { { CKA_PRIVATE,    &ckTrue,  1 } };
    CK_ATTRIBUTE modTmpl[]    = { { CKA_MODIFIABLE, &ckFalse, 1 } };
    CK_ATTRIBUTE sameTmpl[] = {
        { CKA_TOKEN,      &ckFalse, 1 },
        { CKA_PRIVATE,    &ckFalse, 1 },
        { CKA_MODIFIABLE, &ckTrue,  1 },
    };

    rv = create_data_object(session, &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SetAttributeValue(session, obj, tokenTmpl, 1);
    CHECK_RV(rv, "set CKA_TOKEN after creation", CKR_ATTRIBUTE_READ_ONLY);
    rv = funcList->C_SetAttributeValue(session, obj, privTmpl, 1);
    CHECK_RV(rv, "set CKA_PRIVATE after creation", CKR_ATTRIBUTE_READ_ONLY);
    rv = funcList->C_SetAttributeValue(session, obj, modTmpl, 1);
    CHECK_RV(rv, "set CKA_MODIFIABLE after creation",
             CKR_ATTRIBUTE_READ_ONLY);
    expect_bool(session, obj, CKA_TOKEN, CK_FALSE, "CKA_TOKEN unchanged");
    expect_bool(session, obj, CKA_PRIVATE, CK_FALSE, "CKA_PRIVATE unchanged");
    expect_bool(session, obj, CKA_MODIFIABLE, CK_TRUE,
                "CKA_MODIFIABLE unchanged");

    rv = funcList->C_SetAttributeValue(session, obj, sameTmpl,
                                       sizeof(sameTmpl) / sizeof(*sameTmpl));
    CHECK_RV(rv, "restate current CKA_TOKEN/PRIVATE/MODIFIABLE", CKR_OK);

    rv = funcList->C_CopyObject(session, obj, modTmpl, 1, &copy);
    CHECK_RV(rv, "copy with CKA_MODIFIABLE changed", CKR_OK);
    if (rv == CKR_OK) {
        expect_bool(session, copy, CKA_MODIFIABLE, CK_FALSE,
                    "copy has CKA_MODIFIABLE false");
    }

    destroy_obj(session, &copy);
    destroy_obj(session, &obj);
}

#ifndef NO_AES
/* CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE are derived by the token and
 * cannot be supplied when a key is created or generated. */
static void test_derived_attrs_not_settable_at_create(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_ULONG keyLen = 16;
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte keyData[16];
    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,    &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType,  sizeof(keyType)  },
        { CKA_TOKEN,    &ckFalse,  sizeof(ckFalse)  },
        { CKA_PRIVATE,  &ckFalse,  sizeof(ckFalse)  },
        { CKA_VALUE,    keyData,   sizeof(keyData)  },
        { CKA_ALWAYS_SENSITIVE, &ckTrue, sizeof(ckTrue) },
    };
    CK_ULONG createCnt = sizeof(createTmpl) / sizeof(*createTmpl);
    CK_ATTRIBUTE genTmpl[] = {
        { CKA_TOKEN,     &ckFalse, sizeof(ckFalse) },
        { CKA_PRIVATE,   &ckFalse, sizeof(ckFalse) },
        { CKA_VALUE_LEN, &keyLen,  sizeof(keyLen)  },
        { CKA_NEVER_EXTRACTABLE, &ckTrue, sizeof(ckTrue) },
    };
    CK_ULONG genCnt = sizeof(genTmpl) / sizeof(*genTmpl);

    XMEMSET(keyData, 0x5a, sizeof(keyData));

    rv = funcList->C_CreateObject(session, createTmpl, createCnt, &key);
    CHECK_RV(rv, "create key with CKA_ALWAYS_SENSITIVE",
             CKR_ATTRIBUTE_READ_ONLY);
    destroy_obj(session, &key);

    createTmpl[createCnt - 1].type = CKA_NEVER_EXTRACTABLE;
    rv = funcList->C_CreateObject(session, createTmpl, createCnt, &key);
    CHECK_RV(rv, "create key with CKA_NEVER_EXTRACTABLE",
             CKR_ATTRIBUTE_READ_ONLY);
    destroy_obj(session, &key);

    rv = funcList->C_GenerateKey(session, &mech, genTmpl, genCnt, &key);
    CHECK_RV(rv, "generate key with CKA_NEVER_EXTRACTABLE",
             CKR_ATTRIBUTE_READ_ONLY);
    destroy_obj(session, &key);
}
#endif

#ifndef NO_AES
/* A creation template must name one object class; a conflicting duplicate is
 * rejected rather than overriding the class the object was built for. */
static void test_create_class_consistent(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte keyData[16];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &keyClass,  sizeof(keyClass)  },
        { CKA_KEY_TYPE, &keyType,   sizeof(keyType)   },
        { CKA_TOKEN,    &ckFalse,   sizeof(ckFalse)   },
        { CKA_PRIVATE,  &ckFalse,   sizeof(ckFalse)   },
        { CKA_VALUE,    keyData,    sizeof(keyData)   },
        { CKA_CLASS,    &dataClass, sizeof(dataClass) },
    };

    XMEMSET(keyData, 0x3c, sizeof(keyData));
    rv = funcList->C_CreateObject(session, tmpl, sizeof(tmpl) / sizeof(*tmpl),
                                  &key);
    CHECK_RV(rv, "create key with conflicting CKA_CLASS",
             CKR_TEMPLATE_INCONSISTENT);
    destroy_obj(session, &key);
}
#endif

#ifndef NO_AES
/* A rejected multi-attribute update leaves every attribute unchanged. */
static void test_rejected_update_is_atomic(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    byte keyData[16];
    byte valueBuf[64];
    CK_ATTRIBUTE valueAttr = { CKA_VALUE, valueBuf, sizeof(valueBuf) };
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,     &keyClass,         sizeof(keyClass)      },
        { CKA_KEY_TYPE,  &keyType,          sizeof(keyType)       },
        { CKA_TOKEN,     &ckFalse,          sizeof(ckFalse)       },
        { CKA_PRIVATE,   &ckFalse,          sizeof(ckFalse)       },
        { CKA_SENSITIVE, &ckTrue,           sizeof(ckTrue)        },
        { CKA_LABEL,     (void*)dataLabel,  sizeof(dataLabel) - 1 },
        { CKA_VALUE,     keyData,           sizeof(keyData)       },
    };
    CK_ATTRIBUTE labelAndClass[] = {
        { CKA_LABEL, (void*)newLabel, sizeof(newLabel) - 1 },
        { CKA_CLASS, &dataClass,      sizeof(dataClass)    },
    };
    CK_ATTRIBUTE labelAndSensitive[] = {
        { CKA_LABEL,     (void*)newLabel, sizeof(newLabel) - 1 },
        { CKA_SENSITIVE, &ckFalse,        sizeof(ckFalse)      },
    };
    CK_ATTRIBUTE valueAndClass[] = {
        { CKA_VALUE, (void*)newLabel, sizeof(newLabel) - 1 },
        { CKA_CLASS, &keyClass,       sizeof(keyClass)     },
    };

    XMEMSET(keyData, 0x7e, sizeof(keyData));
    rv = funcList->C_CreateObject(session, keyTmpl,
                                  sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    CHECK_RV(rv, "create labelled secret key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, key, labelAndClass, 2);
        CHECK_RV(rv, "set label with read-only class", CKR_ATTRIBUTE_READ_ONLY);
        expect_label(session, key, dataLabel, sizeof(dataLabel) - 1,
                     "label unchanged after rejected class update");

        rv = funcList->C_SetAttributeValue(session, key, labelAndSensitive, 2);
        CHECK_RV(rv, "set label with sensitive cleared",
                 CKR_ATTRIBUTE_READ_ONLY);
        expect_label(session, key, dataLabel, sizeof(dataLabel) - 1,
                     "label unchanged after rejected sensitive update");
    }

    rv = create_data_object(session, &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, obj, valueAndClass, 2);
        CHECK_RV(rv, "set value with read-only class", CKR_ATTRIBUTE_READ_ONLY);
        rv = funcList->C_GetAttributeValue(session, obj, &valueAttr, 1);
        CHECK_TRUE(rv == CKR_OK &&
                   valueAttr.ulValueLen == sizeof(dataValue) - 1 &&
                   XMEMCMP(valueBuf, dataValue, sizeof(dataValue) - 1) == 0,
                   "value unchanged after rejected class update");
    }

    destroy_obj(session, &obj);
    destroy_obj(session, &key);
}
#endif

/* Attribute lengths beyond what the library stores are rejected before any
 * value is read, for both generic and key component attributes. */
static void test_attr_length_range(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG wrapLen = 0;
    CK_ATTRIBUTE labelTmpl[] = {
        { CKA_LABEL, (void*)newLabel, (CK_ULONG)INT_MAX + 1 },
    };
#ifndef NO_RSA
    CK_OBJECT_CLASS rsaClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_ATTRIBUTE rsaTmpl[] = {
        { CKA_CLASS,            &rsaClass,         sizeof(rsaClass)          },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_TOKEN,            &ckFalse,          sizeof(ckFalse)           },
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
#endif
#ifndef NO_DH
    CK_OBJECT_CLASS dhClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE dhType = CKK_DH;
    CK_ATTRIBUTE dhTmpl[] = {
        { CKA_CLASS,    &dhClass,       sizeof(dhClass)        },
        { CKA_KEY_TYPE, &dhType,        sizeof(dhType)         },
        { CKA_TOKEN,    &ckFalse,       sizeof(ckFalse)        },
        { CKA_PRIVATE,  &ckFalse,       sizeof(ckFalse)        },
        { CKA_PRIME,    dh_ffdhe2048_p, sizeof(dh_ffdhe2048_p) },
        { CKA_BASE,     dh_ffdhe2048_g, sizeof(dh_ffdhe2048_g) },
        { CKA_VALUE,    dh_2048_pub,    sizeof(dh_2048_pub)    },
    };
#endif

    rv = create_data_object(session, &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, obj, labelTmpl, 1);
        CHECK_RV(rv, "set label with oversized length",
                 CKR_ATTRIBUTE_VALUE_INVALID);
        expect_label(session, obj, dataLabel, sizeof(dataLabel) - 1,
                     "label unchanged after oversized length");
    }
    destroy_obj(session, &obj);

    /* Only a 64-bit CK_ULONG can carry a length whose low 32 bits look
     * valid. */
    if (sizeof(CK_ULONG) <= 4)
        return;
    wrapLen = (CK_ULONG)1 << 16 << 16;
#ifndef NO_RSA
    rsaTmpl[6].ulValueLen += wrapLen;
    rv = funcList->C_CreateObject(session, rsaTmpl,
                                  sizeof(rsaTmpl) / sizeof(*rsaTmpl), &key);
    CHECK_RV(rv, "create RSA key with oversized prime length",
             CKR_ATTRIBUTE_VALUE_INVALID);
    destroy_obj(session, &key);
#endif
#ifndef NO_DH
    dhTmpl[4].ulValueLen += wrapLen;
    rv = funcList->C_CreateObject(session, dhTmpl,
                                  sizeof(dhTmpl) / sizeof(*dhTmpl), &key);
    CHECK_RV(rv, "create DH key with oversized prime length",
             CKR_ATTRIBUTE_VALUE_INVALID);
    destroy_obj(session, &key);
#endif
    (void)wrapLen;
    (void)key;
}

#ifndef NO_AES
/* Keys cannot be marked as requiring per-use authentication, which the token
 * does not enforce. */
static void test_always_authenticate_rejected(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte keyData[16];
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType,  sizeof(keyType)  },
        { CKA_TOKEN,    &ckFalse,  sizeof(ckFalse)  },
        { CKA_PRIVATE,  &ckFalse,  sizeof(ckFalse)  },
        { CKA_VALUE,    keyData,   sizeof(keyData)  },
        { CKA_ALWAYS_AUTHENTICATE, &ckTrue, sizeof(ckTrue) },
    };
    CK_ULONG keyCnt = sizeof(keyTmpl) / sizeof(*keyTmpl);
    CK_ATTRIBUTE setTrue[]  = { { CKA_ALWAYS_AUTHENTICATE, &ckTrue,  1 } };
    CK_ATTRIBUTE setFalse[] = { { CKA_ALWAYS_AUTHENTICATE, &ckFalse, 1 } };

    XMEMSET(keyData, 0x42, sizeof(keyData));
    rv = funcList->C_CreateObject(session, keyTmpl, keyCnt, &key);
    CHECK_RV(rv, "create key requiring per-use authentication",
             CKR_ATTRIBUTE_VALUE_INVALID);
    destroy_obj(session, &key);

    /* Create without the attribute, then try to turn it on. */
    rv = funcList->C_CreateObject(session, keyTmpl, keyCnt - 1, &key);
    CHECK_RV(rv, "create key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, key, setTrue, 1);
        CHECK_RV(rv, "set CKA_ALWAYS_AUTHENTICATE true",
                 CKR_ATTRIBUTE_VALUE_INVALID);
        expect_bool(session, key, CKA_ALWAYS_AUTHENTICATE, CK_FALSE,
                    "CKA_ALWAYS_AUTHENTICATE remains false");
        rv = funcList->C_SetAttributeValue(session, key, setFalse, 1);
        CHECK_RV(rv, "set CKA_ALWAYS_AUTHENTICATE false", CKR_OK);
    }
    destroy_obj(session, &key);
}
#endif

/* A byte-string attribute with a length must come with a value. */
static void test_data_attr_requires_value(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE bad = CK_INVALID_HANDLE;
    CK_ATTRIBUTE labelTmpl[] = { { CKA_LABEL, NULL, 5 } };
    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,   &dataClass,       sizeof(dataClass)     },
        { CKA_TOKEN,   &ckFalse,         sizeof(ckFalse)       },
        { CKA_PRIVATE, &ckFalse,         sizeof(ckFalse)       },
        { CKA_VALUE,   (void*)dataValue, sizeof(dataValue) - 1 },
        { CKA_ID,      NULL,             4                     },
    };

    rv = create_data_object(session, &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, obj, labelTmpl, 1);
        CHECK_RV(rv, "set label with length and no value",
                 CKR_ATTRIBUTE_VALUE_INVALID);
        expect_label(session, obj, dataLabel, sizeof(dataLabel) - 1,
                     "label unchanged after missing value");
    }
    destroy_obj(session, &obj);

    rv = funcList->C_CreateObject(session, createTmpl,
                                  sizeof(createTmpl) / sizeof(*createTmpl),
                                  &bad);
    CHECK_RV(rv, "create object with CKA_ID length and no value",
             CKR_ATTRIBUTE_VALUE_INVALID);
    destroy_obj(session, &bad);
}

/* An empty CKA_START_DATE/CKA_END_DATE, as read from an object without
 * dates, can be written back and clears a set date. */
static void check_date_roundtrip(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type,
                                 const char* name)
{
    CK_RV rv;
    CK_DATE date = { {'2','0','3','0'}, {'0','6'}, {'1','5'} };
    CK_DATE got;
    CK_ATTRIBUTE getAttr = { type, &got, sizeof(got) };
    CK_ATTRIBUTE emptyNull[] = { { type, NULL, 0 } };
    CK_ATTRIBUTE emptyBuf[]  = { { type, &got, 0 } };
    CK_ATTRIBUTE setDate[]   = { { type, &date, sizeof(date) } };

    rv = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
    CHECK_TRUE(rv == CKR_OK && getAttr.ulValueLen == 0, name);

    rv = funcList->C_SetAttributeValue(session, obj, emptyNull, 1);
    CHECK_RV(rv, "write back empty date", CKR_OK);

    rv = funcList->C_SetAttributeValue(session, obj, setDate, 1);
    CHECK_RV(rv, "set date", CKR_OK);
    getAttr.ulValueLen = sizeof(got);
    rv = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
    CHECK_TRUE(rv == CKR_OK && getAttr.ulValueLen == sizeof(date) &&
               XMEMCMP(&got, &date, sizeof(date)) == 0, "date read back");

    rv = funcList->C_SetAttributeValue(session, obj, emptyBuf, 1);
    CHECK_RV(rv, "clear date with empty value", CKR_OK);
    getAttr.ulValueLen = sizeof(got);
    rv = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
    CHECK_TRUE(rv == CKR_OK && getAttr.ulValueLen == 0, "date cleared");
}

static void test_empty_date_roundtrip(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;

    rv = create_data_object(session, &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv == CKR_OK) {
        check_date_roundtrip(session, obj, CKA_START_DATE,
                             "unset CKA_START_DATE reads as empty");
        check_date_roundtrip(session, obj, CKA_END_DATE,
                             "unset CKA_END_DATE reads as empty");
    }
    destroy_obj(session, &obj);
}

/* CKA_CERTIFICATE_CATEGORY is consumed as a full CK_ULONG. */
static void test_certificate_category_ulong(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_ULONG category = 2;
    word32 shortCategory = 2;
    byte certData[] = { 0x30, 0x82, 0x01, 0x00 };
    CK_OBJECT_HANDLE cert = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,                &certClass, sizeof(certClass) },
        { CKA_CERTIFICATE_TYPE,     &certType,  sizeof(certType)  },
        { CKA_TOKEN,                &ckFalse,   sizeof(ckFalse)   },
        { CKA_PRIVATE,              &ckFalse,   sizeof(ckFalse)   },
        { CKA_VALUE,                certData,   sizeof(certData)  },
        { CKA_CERTIFICATE_CATEGORY, &category,  sizeof(category)  },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    rv = funcList->C_CreateObject(session, tmpl, cnt, &cert);
    CHECK_RV(rv, "create certificate with category", CKR_OK);
    destroy_obj(session, &cert);

    if (sizeof(CK_ULONG) != sizeof(word32)) {
        tmpl[cnt - 1].pValue = &shortCategory;
        tmpl[cnt - 1].ulValueLen = sizeof(shortCategory);
        rv = funcList->C_CreateObject(session, tmpl, cnt, &cert);
        CHECK_TRUE(rv != CKR_OK, "certificate category shorter than CK_ULONG");
        destroy_obj(session, &cert);
    }
}

#ifdef ATTR_TEST_ALLOC_HOOK
/* A replacement value that cannot be stored leaves the previous one. */
static void test_failed_replace_keeps_value(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    byte big[FAIL_ALLOC_SIZE];
    byte idBuf[16];
    CK_ATTRIBUTE labelTmpl[] = { { CKA_LABEL, big, sizeof(big) } };
    CK_ATTRIBUTE idTmpl[]    = { { CKA_ID,    big, sizeof(big) } };
    CK_ATTRIBUTE idSet[]     = { { CKA_ID, (void*)newLabel,
                                   sizeof(newLabel) - 1 } };
    CK_ATTRIBUTE idGet = { CKA_ID, idBuf, sizeof(idBuf) };

    XMEMSET(big, 'x', sizeof(big));
    rv = create_data_object(session, &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, obj, idSet, 1);
        CHECK_RV(rv, "set CKA_ID", CKR_OK);

        failAllocArmed = 1;
        rv = funcList->C_SetAttributeValue(session, obj, labelTmpl, 1);
        failAllocArmed = 0;
        CHECK_RV(rv, "label replacement out of memory", CKR_DEVICE_MEMORY);
        expect_label(session, obj, dataLabel, sizeof(dataLabel) - 1,
                     "label kept after failed replacement");

        failAllocArmed = 1;
        rv = funcList->C_SetAttributeValue(session, obj, idTmpl, 1);
        failAllocArmed = 0;
        CHECK_RV(rv, "CKA_ID replacement out of memory", CKR_DEVICE_MEMORY);
        rv = funcList->C_GetAttributeValue(session, obj, &idGet, 1);
        CHECK_TRUE(rv == CKR_OK && idGet.ulValueLen == sizeof(newLabel) - 1 &&
                   XMEMCMP(idBuf, newLabel, sizeof(newLabel) - 1) == 0,
                   "CKA_ID kept after failed replacement");
    }
    destroy_obj(session, &obj);
}
#endif

#if defined(WOLFPKCS11_KEYPAIR_GEN_COMMON_LABEL) && \
    defined(HAVE_AES_KEYWRAP) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(NO_RSA) && !defined(NO_AES) && \
    (defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA))
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_OBJECT_CLASS privKeyClass   = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS pubKeyClass    = CKO_PUBLIC_KEY;
static CK_KEY_TYPE aesKeyType = CKK_AES;
static CK_KEY_TYPE rsaKeyType = CKK_RSA;

/* An unwrap template that omits CKA_TOKEN creates session objects, including
 * the companion RSA public key. */
static void test_unwrap_rsa_token_default(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_AES_KEY_WRAP_PAD, NULL, 0 };
    CK_OBJECT_HANDLE wrappingKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubKey = CK_INVALID_HANDLE;
    byte wrapped[2048];
    CK_ULONG wrappedLen = sizeof(wrapped);
    CK_ULONG count = 0;
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_WRAP,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_UNWRAP,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_PRIVATE,  &ckFalse,        sizeof(ckFalse)        },
        { CKA_TOKEN,    &ckFalse,        sizeof(ckFalse)        },
        { CKA_VALUE,    (void*)aes_cbc_key, sizeof(aes_cbc_key) },
    };
    CK_ATTRIBUTE rsaTmpl[] = {
        { CKA_CLASS,            &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,         &rsaKeyType,       sizeof(rsaKeyType)        },
        { CKA_DECRYPT,          &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        { CKA_EXTRACTABLE,      &ckTrue,           sizeof(ckTrue)            },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
        { CKA_TOKEN,            &ckFalse,          sizeof(ckFalse)           },
    };
    CK_ATTRIBUTE unwrapTmpl[] = {
        { CKA_CLASS,    &privKeyClass, sizeof(privKeyClass) },
        { CKA_KEY_TYPE, &rsaKeyType,   sizeof(rsaKeyType)   },
        { CKA_PRIVATE,  &ckFalse,      sizeof(ckFalse)      },
    };
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS,    &pubKeyClass, sizeof(pubKeyClass) },
        { CKA_KEY_TYPE, &rsaKeyType,  sizeof(rsaKeyType)  },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
    };

    rv = funcList->C_CreateObject(session, aesTmpl,
                                  sizeof(aesTmpl) / sizeof(*aesTmpl),
                                  &wrappingKey);
    CHECK_RV(rv, "create AES wrapping key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, rsaTmpl,
                                      sizeof(rsaTmpl) / sizeof(*rsaTmpl),
                                      &privKey);
        CHECK_RV(rv, "create RSA private key", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_WrapKey(session, &mech, wrappingKey, privKey,
                                 wrapped, &wrappedLen);
        CHECK_RV(rv, "wrap RSA private key", CKR_OK);
    }
    destroy_obj(session, &privKey);
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &mech, wrappingKey, wrapped,
                                   wrappedLen, unwrapTmpl,
                                   sizeof(unwrapTmpl) / sizeof(*unwrapTmpl),
                                   &unwrapped);
        CHECK_RV(rv, "unwrap RSA private key without CKA_TOKEN", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjectsInit(session, findTmpl,
                                         sizeof(findTmpl) / sizeof(*findTmpl));
        CHECK_RV(rv, "find companion public key init", CKR_OK);
        if (rv == CKR_OK) {
            rv = funcList->C_FindObjects(session, &pubKey, 1, &count);
            CHECK_RV(rv, "find companion public key", CKR_OK);
            funcList->C_FindObjectsFinal(session);
        }
        CHECK_TRUE(count == 1, "companion public key is a session object");
        if (count != 1)
            pubKey = CK_INVALID_HANDLE;
    }

    destroy_obj(session, &pubKey);
    destroy_obj(session, &unwrapped);
    destroy_obj(session, &wrappingKey);
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
        test_token_attr_is_bool(session);
        test_set_attr_count_range(session);
        test_get_attr_count_range(session);
        test_find_objects_large_max(session);
        test_copy_only_attrs_read_only(session);
#ifndef NO_AES
        test_derived_attrs_not_settable_at_create(session);
        test_create_class_consistent(session);
        test_rejected_update_is_atomic(session);
#endif
        test_attr_length_range(session);
#ifndef NO_AES
        test_always_authenticate_rejected(session);
#endif
        test_data_attr_requires_value(session);
        test_empty_date_roundtrip(session);
        test_certificate_category_ulong(session);
#ifdef ATTR_TEST_ALLOC_HOOK
        test_failed_replace_keeps_value(session);
#endif
#if defined(WOLFPKCS11_KEYPAIR_GEN_COMMON_LABEL) && \
    defined(HAVE_AES_KEYWRAP) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(NO_RSA) && !defined(NO_AES) && \
    (defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA))
        test_unwrap_rsa_token_default(session);
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

    printf("=== wolfPKCS11 attribute validation test ===\n");
#ifdef ATTR_TEST_ALLOC_HOOK
    if (wolfSSL_SetAllocators(test_malloc, test_free, test_realloc) != 0) {
        fprintf(stderr, "FAIL: wolfSSL_SetAllocators\n");
        return 1;
    }
#endif
    run_test();
    return pkcs11_test_summary();
}
