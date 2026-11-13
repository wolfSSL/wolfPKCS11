/* attribute_template_test.c
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
 * CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE and CKA_DERIVE_TEMPLATE.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <limits.h>

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

#define TEST_DIR "./store/attribute_template_test"

#define TMPL_CNT(t) (sizeof(t) / sizeof(*(t)))

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    !defined(WOLFPKCS11_NO_STORE)
    #define TEST_WRAP
#endif
#if defined(TEST_WRAP) && !defined(WOLFPKCS11_CUSTOM_STORE) && \
    !defined(WOLFPKCS11_TPM_STORE) && !defined(WOLFPKCS11_NO_ENV) && \
    !defined(_WIN32)
    #define TEST_TAMPER
    #include <dirent.h>
#endif

static byte soPin[] = "password123456";
static byte userPin[] = "wolfpkcs11-test";

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_OBJECT_CLASS dataClass = CKO_DATA;
static CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
#ifdef TEST_WRAP
static CK_KEY_TYPE aesType = CKK_AES;
#endif
static CK_BYTE keyBytes[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static CK_BYTE exportLabel[] = "export";
static CK_BYTE otherLabel[] = "other";

static CK_RV initialize(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slots[16];
    CK_ULONG count = TMPL_CNT(slots);

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slots, &count);
    if (rv == CKR_OK && count == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK)
        *slot = slots[0];

    return rv;
}

static CK_RV provision_token(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_UTF8CHAR label[32];
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "wolfpkcs11", 10);
    rv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
    if (rv == CKR_OK)
        rv = funcList->C_Login(session, CKU_SO, soPin, sizeof(soPin) - 1);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1);

    if (session != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }
    return rv;
}

static CK_RV open_user_session(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    rv = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(*session, CKU_USER, userPin,
                               sizeof(userPin) - 1);
    }
    return rv;
}

/* Secret key with a template attribute; label NULL leaves CKA_LABEL out. */
static CK_RV create_secret(CK_SESSION_HANDLE session, CK_KEY_TYPE type,
                           CK_ULONG len, CK_BYTE* label, CK_ULONG labelLen,
                           CK_ATTRIBUTE* extra, CK_ULONG extraCnt,
                           CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[16] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    NULL,         sizeof(CK_KEY_TYPE) },
        { CKA_TOKEN,       &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_WRAP,        &ckTrue,      sizeof(ckTrue)      },
        { CKA_UNWRAP,      &ckTrue,      sizeof(ckTrue)      },
        { CKA_DERIVE,      &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,       keyBytes,     0                   },
    };
    CK_ULONG cnt = 10;
    CK_ULONG i;
    CK_ULONG j;
    CK_ULONG base;

    tmpl[1].pValue = &type;
    tmpl[9].ulValueLen = len;
    if (label != NULL) {
        tmpl[cnt].type = CKA_LABEL;
        tmpl[cnt].pValue = label;
        tmpl[cnt].ulValueLen = labelLen;
        cnt++;
    }
    /* An extra attribute replaces a default of the same type. */
    base = cnt;
    for (i = 0; i < extraCnt; i++) {
        for (j = 0; j < base && tmpl[j].type != extra[i].type; j++)
            ;
        if (j == base)
            j = cnt++;
        tmpl[j] = extra[i];
    }

    return funcList->C_CreateObject(session, tmpl, cnt, key);
}

#if defined(TEST_WRAP) || defined(WOLFPKCS11_CONCATENATE) || \
    defined(WOLFSSL_HAVE_PRF) || defined(WOLFPKCS11_HKDF)
static CK_BBOOL get_bool(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                         CK_ATTRIBUTE_TYPE type)
{
    CK_BBOOL val = 0xFF;
    CK_ATTRIBUTE attr;

    attr.type = type;
    attr.pValue = &val;
    attr.ulValueLen = sizeof(val);
    if (funcList->C_GetAttributeValue(session, obj, &attr, 1) != CKR_OK)
        return 0xFF;
    return val;
}
#endif

static void test_set_get(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE inner[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass)     },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType)     },
        { CKA_LABEL,    exportLabel,  sizeof(exportLabel) - 1 },
    };
    CK_ATTRIBUTE wrapTmpl[] = {
        { CKA_WRAP_TEMPLATE, inner, sizeof(inner) },
    };
    CK_ATTRIBUTE get[3];
    CK_ATTRIBUTE outer;
    CK_OBJECT_CLASS gotClass = 0;
    CK_KEY_TYPE gotType = 0;
    CK_BYTE gotLabel[16];
    CK_BYTE shortLabel[2];
    CK_ATTRIBUTE nested[] = {
        { CKA_UNWRAP_TEMPLATE, inner, sizeof(inner) },
    };
    CK_ATTRIBUTE unknown[] = {
        { 0x7FFFFF01UL, keyBytes, 4 },
    };
    CK_ATTRIBUTE badBool[] = {
        { CKA_SENSITIVE, keyBytes, 2 },
    };
    CK_ATTRIBUTE many[33];
    static CK_BYTE big[2100];
    CK_ATTRIBUTE largeInner[] = {
        { CKA_LABEL, big, sizeof(big) },
    };
    CK_ULONG gen = CKM_AES_KEY_GEN;
    CK_ATTRIBUTE fixedInner[] = {
        { CKA_KEY_GEN_MECHANISM, &gen, sizeof(gen) },
    };
    CK_ATTRIBUTE twice[2];
    CK_ATTRIBUTE repeated[] = {
        { CKA_LABEL, exportLabel, sizeof(exportLabel) - 1 },
        { CKA_LABEL, otherLabel,  sizeof(otherLabel) - 1  },
    };
    CK_ATTRIBUTE valueInner[] = {
        { CKA_VALUE, keyBytes, sizeof(keyBytes) },
    };
    CK_ATTRIBUTE primeInner[] = {
        { CKA_PRIME_1, keyBytes, sizeof(keyBytes) },
    };
    CK_ATTRIBUTE seedInner[] = {
        { CKA_SEED, keyBytes, sizeof(keyBytes) },
    };
    CK_ATTRIBUTE authInner[] = {
        { CKA_ALWAYS_AUTHENTICATE, &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE trustedInner[] = {
        { CKA_TRUSTED, &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE bad;
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,         &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,         &ckFalse,   sizeof(ckFalse)   },
        { CKA_WRAP_TEMPLATE, inner,      sizeof(inner)     },
    };
    CK_ULONG i;

    printf("\n--- set and get ---\n");
    rv = create_secret(session, genericType, 32, NULL, 0, wrapTmpl, 1, &kek);
    CHECK_RV(rv, "create key with CKA_WRAP_TEMPLATE", CKR_OK);
    if (rv != CKR_OK)
        return;

    outer.type = CKA_WRAP_TEMPLATE;
    outer.pValue = NULL;
    outer.ulValueLen = 0;
    rv = funcList->C_GetAttributeValue(session, kek, &outer, 1);
    CHECK_RV(rv, "template length", CKR_OK);
    CHECK_TRUE(outer.ulValueLen == sizeof(inner), "template length value");

    XMEMSET(get, 0, sizeof(get));
    outer.pValue = get;
    outer.ulValueLen = sizeof(get);
    rv = funcList->C_GetAttributeValue(session, kek, &outer, 1);
    CHECK_RV(rv, "element lengths", CKR_OK);
    CHECK_TRUE(get[0].type == CKA_CLASS && get[1].type == CKA_KEY_TYPE &&
               get[2].type == CKA_LABEL, "element types");
    CHECK_TRUE(get[0].ulValueLen == sizeof(CK_OBJECT_CLASS) &&
               get[1].ulValueLen == sizeof(CK_KEY_TYPE) &&
               get[2].ulValueLen == sizeof(exportLabel) - 1,
               "element length values");

    get[0].pValue = &gotClass;
    get[1].pValue = &gotType;
    get[2].pValue = gotLabel;
    get[2].ulValueLen = sizeof(gotLabel);
    rv = funcList->C_GetAttributeValue(session, kek, &outer, 1);
    CHECK_RV(rv, "element values", CKR_OK);
    CHECK_TRUE(gotClass == CKO_SECRET_KEY && gotType == CKK_GENERIC_SECRET &&
               get[2].ulValueLen == sizeof(exportLabel) - 1 &&
               XMEMCMP(gotLabel, exportLabel, sizeof(exportLabel) - 1) == 0,
               "element value contents");

    get[2].pValue = shortLabel;
    get[2].ulValueLen = sizeof(shortLabel);
    rv = funcList->C_GetAttributeValue(session, kek, &outer, 1);
    CHECK_RV(rv, "short element buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(get[2].ulValueLen == CK_UNAVAILABLE_INFORMATION &&
               get[0].ulValueLen == sizeof(CK_OBJECT_CLASS),
               "short element marked unavailable");

    outer.ulValueLen = 2 * sizeof(CK_ATTRIBUTE);
    rv = funcList->C_GetAttributeValue(session, kek, &outer, 1);
    CHECK_RV(rv, "short array buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(outer.ulValueLen == CK_UNAVAILABLE_INFORMATION,
               "short array marked unavailable");

    outer.type = CKA_UNWRAP_TEMPLATE;
    outer.pValue = NULL;
    outer.ulValueLen = 1;
    rv = funcList->C_GetAttributeValue(session, kek, &outer, 1);
    CHECK_RV(rv, "unset template", CKR_OK);
    CHECK_TRUE(outer.ulValueLen == 0, "unset template is empty");

    rv = funcList->C_SetAttributeValue(session, kek, wrapTmpl, 1);
    CHECK_RV(rv, "set after creation", CKR_ATTRIBUTE_READ_ONLY);
    rv = funcList->C_CopyObject(session, kek, wrapTmpl, 1, &copy);
    CHECK_RV(rv, "change in copy", CKR_ATTRIBUTE_READ_ONLY);
    rv = funcList->C_CopyObject(session, kek, NULL, 0, &copy);
    CHECK_RV(rv, "copy", CKR_OK);
    if (rv == CKR_OK) {
        outer.type = CKA_WRAP_TEMPLATE;
        outer.pValue = NULL;
        outer.ulValueLen = 0;
        rv = funcList->C_GetAttributeValue(session, copy, &outer, 1);
        CHECK_RV(rv, "copy template", CKR_OK);
        CHECK_TRUE(outer.ulValueLen == sizeof(inner), "copy keeps template");
        funcList->C_DestroyObject(session, copy);
    }
    funcList->C_DestroyObject(session, kek);

    bad.type = CKA_WRAP_TEMPLATE;
    bad.pValue = nested;
    bad.ulValueLen = sizeof(nested);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "nested template", CKR_ATTRIBUTE_VALUE_INVALID);
    bad.pValue = inner;
    bad.ulValueLen = sizeof(inner) - 1;
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "partial attribute", CKR_ATTRIBUTE_VALUE_INVALID);
    bad.pValue = unknown;
    bad.ulValueLen = sizeof(unknown);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "unknown inner type", CKR_ATTRIBUTE_VALUE_INVALID);
    bad.pValue = badBool;
    bad.ulValueLen = sizeof(badBool);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "bad inner length", CKR_ATTRIBUTE_VALUE_INVALID);
    for (i = 0; i < TMPL_CNT(many); i++) {
        many[i].type = CKA_LABEL;
        many[i].pValue = exportLabel;
        many[i].ulValueLen = 1;
    }
    bad.pValue = many;
    bad.ulValueLen = sizeof(many);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "too many attributes", CKR_ATTRIBUTE_VALUE_INVALID);
    bad.pValue = largeInner;
    bad.ulValueLen = sizeof(largeInner);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "template too large", CKR_ATTRIBUTE_VALUE_INVALID);
    bad.type = CKA_UNWRAP_TEMPLATE;
    bad.pValue = fixedInner;
    bad.ulValueLen = sizeof(fixedInner);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "unwrap template sets a fixed attribute",
             CKR_ATTRIBUTE_VALUE_INVALID);
    bad.type = CKA_WRAP_TEMPLATE;
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "wrap template matches a fixed attribute", CKR_OK);
    if (rv == CKR_OK)
        funcList->C_DestroyObject(session, obj);
    twice[0] = wrapTmpl[0];
    twice[1] = wrapTmpl[0];
    rv = create_secret(session, genericType, 32, NULL, 0, twice, 2, &obj);
    CHECK_RV(rv, "template given twice", CKR_TEMPLATE_INCONSISTENT);
    bad.pValue = repeated;
    bad.ulValueLen = sizeof(repeated);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "repeated inner attribute", CKR_ATTRIBUTE_VALUE_INVALID);
    bad.pValue = valueInner;
    bad.ulValueLen = sizeof(valueInner);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "key value in wrap template", CKR_ATTRIBUTE_VALUE_INVALID);
    bad.type = CKA_DERIVE_TEMPLATE;
    bad.pValue = primeInner;
    bad.ulValueLen = sizeof(primeInner);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "RSA prime in derive template",
             CKR_ATTRIBUTE_VALUE_INVALID);
    bad.pValue = seedInner;
    bad.ulValueLen = sizeof(seedInner);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "seed in derive template", CKR_ATTRIBUTE_VALUE_INVALID);
    bad.pValue = authInner;
    bad.ulValueLen = sizeof(authInner);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "always authenticate in derive template",
             CKR_ATTRIBUTE_VALUE_INVALID);
    bad.type = CKA_WRAP_TEMPLATE;
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "wrap template matches always authenticate", CKR_OK);
    if (rv == CKR_OK)
        funcList->C_DestroyObject(session, obj);
    bad.type = CKA_UNWRAP_TEMPLATE;
    bad.pValue = trustedInner;
    bad.ulValueLen = sizeof(trustedInner);
    rv = create_secret(session, genericType, 32, NULL, 0, &bad, 1, &obj);
    CHECK_RV(rv, "trusted in unwrap template", CKR_ATTRIBUTE_VALUE_INVALID);

    rv = funcList->C_CreateObject(session, dataTmpl, TMPL_CNT(dataTmpl), &obj);
    CHECK_RV(rv, "template on data object", CKR_ATTRIBUTE_TYPE_INVALID);
    rv = funcList->C_CreateObject(session, dataTmpl, TMPL_CNT(dataTmpl) - 1,
                                  &obj);
    CHECK_RV(rv, "create data object", CKR_OK);
    if (rv == CKR_OK) {
        outer.type = CKA_WRAP_TEMPLATE;
        outer.pValue = NULL;
        outer.ulValueLen = 0;
        rv = funcList->C_GetAttributeValue(session, obj, &outer, 1);
        CHECK_RV(rv, "get on data object", CKR_ATTRIBUTE_TYPE_INVALID);
        funcList->C_DestroyObject(session, obj);
    }
}

#ifdef TEST_WRAP
static void test_wrap(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_BYTE iv[16];
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_ATTRIBUTE inner[] = {
        { CKA_KEY_TYPE, &aesType,    sizeof(aesType)         },
        { CKA_LABEL,    exportLabel, sizeof(exportLabel) - 1 },
    };
    CK_ATTRIBUTE wrapTmpl[] = {
        { CKA_WRAP_TEMPLATE, inner, sizeof(inner) },
    };
    CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE plainKek = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE match = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE wrongLabel = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE wrongType = CK_INVALID_HANDLE;
    CK_BYTE out[64];
    CK_ULONG outLen;

    printf("\n--- CKA_WRAP_TEMPLATE ---\n");
    XMEMSET(iv, 0, sizeof(iv));
    rv = create_secret(session, aesType, 32, NULL, 0, wrapTmpl, 1, &kek);
    CHECK_RV(rv, "create restricted KEK", CKR_OK);
    if (rv == CKR_OK)
        rv = create_secret(session, aesType, 32, NULL, 0, NULL, 0, &plainKek);
    if (rv == CKR_OK) {
        rv = create_secret(session, aesType, 16, exportLabel,
                           sizeof(exportLabel) - 1, NULL, 0, &match);
    }
    if (rv == CKR_OK) {
        rv = create_secret(session, aesType, 16, otherLabel,
                           sizeof(otherLabel) - 1, NULL, 0, &wrongLabel);
    }
    if (rv == CKR_OK) {
        rv = create_secret(session, genericType, 16, exportLabel,
                           sizeof(exportLabel) - 1, NULL, 0, &wrongType);
    }
    CHECK_RV(rv, "create keys", CKR_OK);

    if (rv == CKR_OK) {
        outLen = sizeof(out);
        rv = funcList->C_WrapKey(session, &mech, kek, match, out, &outLen);
        CHECK_RV(rv, "wrap matching key", CKR_OK);

        outLen = 0;
        rv = funcList->C_WrapKey(session, &mech, kek, wrongLabel, NULL,
                                 &outLen);
        CHECK_RV(rv, "length query, wrong label", CKR_KEY_HANDLE_INVALID);
        outLen = sizeof(out);
        rv = funcList->C_WrapKey(session, &mech, kek, wrongLabel, out,
                                 &outLen);
        CHECK_RV(rv, "wrap wrong label", CKR_KEY_HANDLE_INVALID);
        outLen = sizeof(out);
        rv = funcList->C_WrapKey(session, &mech, kek, wrongType, out, &outLen);
        CHECK_RV(rv, "wrap wrong key type", CKR_KEY_HANDLE_INVALID);
        outLen = sizeof(out);
        rv = funcList->C_WrapKey(session, &mech, plainKek, wrongLabel, out,
                                 &outLen);
        CHECK_RV(rv, "unrestricted KEK (control)", CKR_OK);
    }

    funcList->C_DestroyObject(session, wrongType);
    funcList->C_DestroyObject(session, wrongLabel);
    funcList->C_DestroyObject(session, match);
    funcList->C_DestroyObject(session, plainKek);
    funcList->C_DestroyObject(session, kek);
}

static void test_unwrap(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_BYTE iv[16];
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_ATTRIBUTE inner[] = {
        { CKA_SENSITIVE,   &ckTrue,  sizeof(ckTrue)  },
        { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
    };
    CK_ATTRIBUTE unwrapTmpl[] = {
        { CKA_UNWRAP_TEMPLATE, inner, sizeof(inner) },
    };
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,       &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
    };
    CK_ATTRIBUTE dupTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &aesType,     sizeof(aesType)     },
        { CKA_EXTRACTABLE, &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
    };
    CK_ULONG valueLen = 32;
    CK_ATTRIBUTE lenInner[] = {
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
    };
    CK_ATTRIBUTE lenTmpl = { CKA_UNWRAP_TEMPLATE, lenInner, sizeof(lenInner) };
    CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE lenKek = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key32 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE got = CK_INVALID_HANDLE;
    CK_BYTE blob[64];
    CK_ULONG blobLen = sizeof(blob);

    printf("\n--- CKA_UNWRAP_TEMPLATE ---\n");
    XMEMSET(iv, 0, sizeof(iv));
    rv = create_secret(session, aesType, 32, NULL, 0, unwrapTmpl, 1, &kek);
    CHECK_RV(rv, "create KEK", CKR_OK);
    if (rv == CKR_OK)
        rv = create_secret(session, aesType, 16, NULL, 0, NULL, 0, &key);
    if (rv == CKR_OK)
        rv = funcList->C_WrapKey(session, &mech, kek, key, blob, &blobLen);
    CHECK_RV(rv, "wrap key", CKR_OK);

    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &mech, kek, blob, blobLen,
                                   keyTmpl, TMPL_CNT(keyTmpl) - 1, &got);
        CHECK_RV(rv, "unwrap", CKR_OK);
        if (rv == CKR_OK) {
            CHECK_TRUE(get_bool(session, got, CKA_SENSITIVE) == CK_TRUE &&
                       get_bool(session, got, CKA_EXTRACTABLE) == CK_FALSE,
                       "unwrap template applied");
            funcList->C_DestroyObject(session, got);
        }

        got = CK_INVALID_HANDLE;
        rv = funcList->C_UnwrapKey(session, &mech, kek, blob, blobLen,
                                   keyTmpl, TMPL_CNT(keyTmpl), &got);
        CHECK_RV(rv, "conflicting template", CKR_TEMPLATE_INCONSISTENT);
        CHECK_TRUE(got == CK_INVALID_HANDLE, "no key on conflict");

        rv = funcList->C_UnwrapKey(session, &mech, kek, blob, blobLen,
                                   dupTmpl, TMPL_CNT(dupTmpl), &got);
        CHECK_RV(rv, "repeated attribute", CKR_TEMPLATE_INCONSISTENT);

        keyTmpl[3].pValue = &ckFalse;
        rv = funcList->C_UnwrapKey(session, &mech, kek, blob, blobLen,
                                   keyTmpl, TMPL_CNT(keyTmpl), &got);
        CHECK_RV(rv, "agreeing template", CKR_OK);
        if (rv == CKR_OK)
            funcList->C_DestroyObject(session, got);

        rv = funcList->C_UnwrapKey(session, &mech, kek, blob, blobLen,
                                   keyTmpl, (CK_ULONG)INT_MAX + 1, &got);
        CHECK_RV(rv, "oversized attribute count", CKR_ARGUMENTS_BAD);

        rv = create_secret(session, aesType, 32, NULL, 0, &lenTmpl, 1,
                           &lenKek);
        if (rv == CKR_OK)
            rv = create_secret(session, aesType, 32, NULL, 0, NULL, 0, &key32);
        CHECK_RV(rv, "create KEK with length template", CKR_OK);
    }
    if (key32 != CK_INVALID_HANDLE) {
        blobLen = sizeof(blob);
        got = CK_INVALID_HANDLE;
        rv = funcList->C_WrapKey(session, &mech, lenKek, key, blob, &blobLen);
        if (rv == CKR_OK) {
            rv = funcList->C_UnwrapKey(session, &mech, lenKek, blob, blobLen,
                                       keyTmpl, TMPL_CNT(keyTmpl) - 1, &got);
        }
        CHECK_RV(rv, "unwrapped length differs from template",
                 CKR_TEMPLATE_INCONSISTENT);
        CHECK_TRUE(got == CK_INVALID_HANDLE, "no key on length mismatch");

        blobLen = sizeof(blob);
        rv = funcList->C_WrapKey(session, &mech, lenKek, key32, blob,
                                 &blobLen);
        if (rv == CKR_OK) {
            rv = funcList->C_UnwrapKey(session, &mech, lenKek, blob, blobLen,
                                       keyTmpl, TMPL_CNT(keyTmpl) - 1, &got);
        }
        CHECK_RV(rv, "unwrapped length matches template", CKR_OK);
        if (rv == CKR_OK)
            funcList->C_DestroyObject(session, got);
    }

    funcList->C_DestroyObject(session, key32);
    funcList->C_DestroyObject(session, lenKek);
    funcList->C_DestroyObject(session, key);
    funcList->C_DestroyObject(session, kek);
}
#endif

#ifdef WOLFPKCS11_CONCATENATE
static CK_RV get_label(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                       CK_BYTE* label, CK_ULONG* len)
{
    CK_ATTRIBUTE attr;
    CK_RV rv;

    attr.type = CKA_LABEL;
    attr.pValue = label;
    attr.ulValueLen = *len;
    rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    *len = attr.ulValueLen;
    return rv;
}

static void test_derive(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_BYTE derivedLabel[] = "derived";
    CK_ATTRIBUTE baseInner[] = {
        { CKA_LABEL, derivedLabel, sizeof(derivedLabel) - 1 },
    };
    CK_ATTRIBUTE otherInner[] = {
        { CKA_LABEL, otherLabel, sizeof(otherLabel) - 1 },
    };
    CK_ATTRIBUTE signInner[] = {
        { CKA_SIGN, &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE extra;
    CK_BYTE data[16];
    CK_KEY_DERIVATION_STRING_DATA strData = { data, sizeof(data) };
    CK_MECHANISM mech = { CKM_CONCATENATE_BASE_AND_DATA, &strData,
                          sizeof(strData) };
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE signer = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE got = CK_INVALID_HANDLE;
    CK_MECHANISM keyMech = { CKM_CONCATENATE_BASE_AND_KEY, &other,
                             sizeof(other) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass)     },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType)     },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)         },
        { CKA_LABEL,    otherLabel,   sizeof(otherLabel) - 1  },
    };
    CK_ATTRIBUTE dupTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass)       },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType)       },
        { CKA_LABEL,    derivedLabel, sizeof(derivedLabel) - 1  },
        { CKA_LABEL,    otherLabel,   sizeof(otherLabel) - 1    },
    };
    CK_BYTE label[16];
    CK_ULONG labelLen;

    printf("\n--- CKA_DERIVE_TEMPLATE ---\n");
    XMEMSET(data, 0x5A, sizeof(data));
    extra.type = CKA_DERIVE_TEMPLATE;
    extra.pValue = baseInner;
    extra.ulValueLen = sizeof(baseInner);
    rv = create_secret(session, genericType, 32, NULL, 0, &extra, 1, &base);
    if (rv == CKR_OK) {
        extra.pValue = otherInner;
        extra.ulValueLen = sizeof(otherInner);
        rv = create_secret(session, genericType, 32, NULL, 0, &extra, 1,
                           &other);
    }
    if (rv == CKR_OK) {
        extra.pValue = signInner;
        extra.ulValueLen = sizeof(signInner);
        rv = create_secret(session, genericType, 32, NULL, 0, &extra, 1,
                           &signer);
    }
    CHECK_RV(rv, "create base keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_DeriveKey(session, &mech, base, tmpl, TMPL_CNT(tmpl) - 1,
                               &got);
    CHECK_RV(rv, "derive", CKR_OK);
    if (rv == CKR_OK) {
        labelLen = sizeof(label);
        rv = get_label(session, got, label, &labelLen);
        CHECK_TRUE(rv == CKR_OK && labelLen == sizeof(derivedLabel) - 1 &&
                   XMEMCMP(label, derivedLabel, labelLen) == 0,
                   "derive template applied");
        funcList->C_DestroyObject(session, got);
    }

    got = CK_INVALID_HANDLE;
    rv = funcList->C_DeriveKey(session, &mech, base, tmpl, TMPL_CNT(tmpl),
                               &got);
    CHECK_RV(rv, "conflicting template", CKR_TEMPLATE_INCONSISTENT);
    CHECK_TRUE(got == CK_INVALID_HANDLE, "no key on conflict");
    rv = funcList->C_DeriveKey(session, &mech, base, dupTmpl,
                               TMPL_CNT(dupTmpl), &got);
    CHECK_RV(rv, "repeated attribute", CKR_TEMPLATE_INCONSISTENT);
    rv = funcList->C_DeriveKey(session, &mech, base, tmpl,
                               (CK_ULONG)INT_MAX + 1, &got);
    CHECK_RV(rv, "oversized attribute count", CKR_ARGUMENTS_BAD);

    rv = funcList->C_DeriveKey(session, &keyMech, base, tmpl,
                               TMPL_CNT(tmpl) - 1, &got);
    CHECK_RV(rv, "base and other key templates conflict",
             CKR_TEMPLATE_INCONSISTENT);

    keyMech.pParameter = &signer;
    rv = funcList->C_DeriveKey(session, &keyMech, base, tmpl,
                               TMPL_CNT(tmpl) - 1, &got);
    CHECK_RV(rv, "base and other key templates", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(get_bool(session, got, CKA_SIGN) == CK_TRUE,
                   "other key template applied");
        funcList->C_DestroyObject(session, got);
    }

out:
    funcList->C_DestroyObject(session, signer);
    funcList->C_DestroyObject(session, other);
    funcList->C_DestroyObject(session, base);
}
#endif

#if defined(WOLFPKCS11_CONCATENATE) && defined(DEBUG_WOLFPKCS11) && \
    !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_NSS)
#define TEST_LOGIN_RACE
#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Object_SetFindHook(void (*hook)(void));
#ifdef __cplusplus
}
#endif

static CK_SESSION_HANDLE hookSession = CK_INVALID_HANDLE;
static CK_RV hookLoginRv = CKR_GENERAL_ERROR;

/* Runs inside C_DeriveKey after the private base key was not found. */
static void hook_login(void)
{
    WP11_Object_SetFindHook(NULL);
    hookLoginRv = funcList->C_Login(hookSession, CKU_USER, userPin,
                                    sizeof(userPin) - 1);
}

static void test_derive_login_race(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_ATTRIBUTE inner[] = {
        { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
    };
    CK_ATTRIBUTE extra[] = {
        { CKA_DERIVE_TEMPLATE, inner,   sizeof(inner)  },
        { CKA_TOKEN,           &ckTrue, sizeof(ckTrue) },
        { CKA_PRIVATE,         &ckTrue, sizeof(ckTrue) },
    };
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE got = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_CONCATENATE_BASE_AND_KEY, &other,
                          sizeof(other) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType, sizeof(genericType) },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
    };

    printf("\n--- login during C_DeriveKey ---\n");
    rv = create_secret(session, genericType, 32, NULL, 0, extra,
                       TMPL_CNT(extra), &base);
    if (rv == CKR_OK)
        rv = create_secret(session, genericType, 32, NULL, 0, NULL, 0, &other);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    CHECK_RV(rv, "create keys and log out", CKR_OK);
    if (rv == CKR_OK) {
        hookSession = session;
        WP11_Object_SetFindHook(hook_login);
        rv = funcList->C_DeriveKey(session, &mech, base, tmpl, TMPL_CNT(tmpl),
                                   &got);
        WP11_Object_SetFindHook(NULL);
        CHECK_RV(hookLoginRv, "log in during the derive", CKR_OK);
        CHECK_RV(rv, "base key found only after the merge",
                 CKR_KEY_HANDLE_INVALID);
        if (hookLoginRv != CKR_OK) {
            (void)funcList->C_Login(session, CKU_USER, userPin,
                                    sizeof(userPin) - 1);
        }
    }
    funcList->C_DestroyObject(session, got);
    funcList->C_DestroyObject(session, other);
    funcList->C_DestroyObject(session, base);
}
#endif

#ifdef WOLFSSL_HAVE_PRF
static CK_RV tls_derive(CK_SESSION_HANDLE session, CK_ATTRIBUTE* inner,
                        CK_ULONG innerSz)
{
    CK_RV rv;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_BYTE master[48];
    CK_BYTE clientRandom[32];
    CK_BYTE serverRandom[32];
    CK_SSL3_KEY_MAT_OUT keyMat;
    CK_TLS12_KEY_MAT_PARAMS params;
    CK_MECHANISM mech = { CKM_TLS12_KEY_AND_MAC_DERIVE, &params,
                          sizeof(params) };
    CK_ATTRIBUTE extra[] = {
        { CKA_VALUE,           master, sizeof(master) },
        { CKA_DERIVE_TEMPLATE, inner,  innerSz        },
    };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_SENSITIVE, &ckFalse,     sizeof(ckFalse)     },
    };

    XMEMSET(master, 0x11, sizeof(master));
    XMEMSET(clientRandom, 0x22, sizeof(clientRandom));
    XMEMSET(serverRandom, 0x33, sizeof(serverRandom));
    XMEMSET(&keyMat, 0, sizeof(keyMat));
    XMEMSET(&params, 0, sizeof(params));
    params.ulMacSizeInBits = 256;
    params.ulKeySizeInBits = 128;
    params.RandomInfo.pClientRandom = clientRandom;
    params.RandomInfo.ulClientRandomLen = sizeof(clientRandom);
    params.RandomInfo.pServerRandom = serverRandom;
    params.RandomInfo.ulServerRandomLen = sizeof(serverRandom);
    params.pReturnedKeyMaterial = &keyMat;
    params.prfHashMechanism = CKM_SHA256;

    rv = create_secret(session, genericType, 0, NULL, 0, extra,
                       TMPL_CNT(extra), &base);
    if (rv != CKR_OK)
        return rv;
    rv = funcList->C_DeriveKey(session, &mech, base, tmpl, TMPL_CNT(tmpl),
                               NULL);
    if (rv != CKR_OK && keyMat.hClientMacSecret != CK_INVALID_HANDLE)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK &&
            get_bool(session, keyMat.hClientMacSecret, CKA_ENCRYPT) != CK_FALSE)
        rv = CKR_GENERAL_ERROR;
    funcList->C_DestroyObject(session, keyMat.hClientMacSecret);
    funcList->C_DestroyObject(session, keyMat.hServerMacSecret);
    funcList->C_DestroyObject(session, keyMat.hClientKey);
    funcList->C_DestroyObject(session, keyMat.hServerKey);
    funcList->C_DestroyObject(session, base);
    return rv;
}

static void test_tls_derive(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_KEY_TYPE aes = CKK_AES;
    CK_ATTRIBUTE encrypt[] = {
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
    };
    CK_ATTRIBUTE keyType[] = {
        { CKA_KEY_TYPE, &aes, sizeof(aes) },
    };
    CK_ATTRIBUTE noSign[] = {
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_SIGN,     &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ULONG keyLen = 32;
    CK_ATTRIBUTE valueLen[] = {
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_VALUE_LEN, &keyLen,      sizeof(keyLen)      },
    };
    CK_ATTRIBUTE agrees[] = {
        { CKA_KEY_TYPE, &genericType, sizeof(genericType)     },
        { CKA_SIGN,     &ckTrue,      sizeof(ckTrue)          },
        { CKA_WRAP,     &ckFalse,     sizeof(ckFalse)         },
        { CKA_LABEL,    exportLabel,  sizeof(exportLabel) - 1 },
    };

    rv = tls_derive(session, encrypt, sizeof(encrypt));
    CHECK_RV(rv, "TLS derive template enables encrypt", CKR_OK);
    rv = tls_derive(session, keyType, sizeof(keyType));
    CHECK_RV(rv, "TLS derive template sets key type",
             CKR_TEMPLATE_INCONSISTENT);
    rv = tls_derive(session, noSign, sizeof(noSign));
    CHECK_RV(rv, "TLS derive template denies sign",
             CKR_TEMPLATE_INCONSISTENT);
    rv = tls_derive(session, valueLen, sizeof(valueLen));
    CHECK_RV(rv, "TLS derive template length exceeds cipher keys",
             CKR_TEMPLATE_INCONSISTENT);
    keyLen = 16;
    rv = tls_derive(session, valueLen, sizeof(valueLen));
    CHECK_RV(rv, "TLS derive template length fits all keys", CKR_OK);
    rv = tls_derive(session, agrees, sizeof(agrees));
    CHECK_RV(rv, "TLS derive template agrees with MAC keys", CKR_OK);
}
#endif

#ifdef WOLFPKCS11_HKDF
static void test_hkdf_salt(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_ULONG len = 32;
    CK_BYTE info[8];
    CK_HKDF_PARAMS hkdf;
    CK_MECHANISM mech = { CKM_HKDF_DERIVE, &hkdf, sizeof(hkdf) };
    CK_ATTRIBUTE inner[] = {
        { CKA_SIGN, &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE extra = { CKA_DERIVE_TEMPLATE, inner, sizeof(inner) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType, sizeof(genericType) },
        { CKA_TOKEN,       &ckFalse,     sizeof(ckFalse)     },
        { CKA_VALUE_LEN,   &len,         sizeof(len)         },
        { CKA_SIGN,        &ckFalse,     sizeof(ckFalse)     },
    };
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE salt = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE got = CK_INVALID_HANDLE;

    printf("\n--- HKDF salt key template ---\n");
    XMEMSET(info, 0x44, sizeof(info));
    XMEMSET(&hkdf, 0, sizeof(hkdf));
    hkdf.bExtract = CK_TRUE;
    hkdf.bExpand = CK_TRUE;
    hkdf.prfHashMechanism = CKM_SHA256;
    hkdf.ulSaltType = CKF_HKDF_SALT_KEY;
    hkdf.pInfo = info;
    hkdf.ulInfoLen = sizeof(info);
    rv = create_secret(session, genericType, 32, NULL, 0, NULL, 0, &base);
    if (rv == CKR_OK)
        rv = create_secret(session, genericType, 32, NULL, 0, &extra, 1, &salt);
    CHECK_RV(rv, "create base and salt keys", CKR_OK);
    if (rv == CKR_OK) {
        hkdf.hSaltKey = salt;
        rv = funcList->C_DeriveKey(session, &mech, base, tmpl,
                                   TMPL_CNT(tmpl) - 1, &got);
        CHECK_RV(rv, "derive with salt key", CKR_OK);
        if (rv == CKR_OK) {
            CHECK_TRUE(get_bool(session, got, CKA_SIGN) == CK_TRUE,
                       "salt key template applied");
            funcList->C_DestroyObject(session, got);
        }
        got = CK_INVALID_HANDLE;
        rv = funcList->C_DeriveKey(session, &mech, base, tmpl, TMPL_CNT(tmpl),
                                   &got);
        CHECK_RV(rv, "salt key template conflicts", CKR_TEMPLATE_INCONSISTENT);
        CHECK_TRUE(got == CK_INVALID_HANDLE, "no key on salt conflict");
    }
    funcList->C_DestroyObject(session, salt);
    funcList->C_DestroyObject(session, base);
}
#endif

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
static void test_key_pair(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM wrapMech = { CKM_RSA_PKCS, NULL, 0 };
    CK_ULONG bits = 2048;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 };
    CK_ATTRIBUTE inner[] = {
        { CKA_LABEL, exportLabel, sizeof(exportLabel) - 1 },
    };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,           &ckFalse, sizeof(ckFalse) },
        { CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
        { CKA_PUBLIC_EXPONENT, exp,      sizeof(exp)     },
        { CKA_WRAP,            &ckTrue,  sizeof(ckTrue)  },
        { CKA_WRAP_TEMPLATE,   inner,    sizeof(inner)   },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,           &ckFalse, sizeof(ckFalse) },
        { CKA_PRIVATE,         &ckTrue,  sizeof(ckTrue)  },
        { CKA_UNWRAP,          &ckTrue,  sizeof(ckTrue)  },
        { CKA_UNWRAP_TEMPLATE, inner,    sizeof(inner)   },
        { CKA_WRAP_TEMPLATE,   inner,    sizeof(inner)   },
    };
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE match = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE wrong = CK_INVALID_HANDLE;
    CK_ATTRIBUTE outer;
    CK_BYTE out[256];
    CK_ULONG outLen;

    printf("\n--- key pair templates ---\n");
    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
                                     TMPL_CNT(pubTmpl), privTmpl,
                                     TMPL_CNT(privTmpl), &pub, &priv);
    CHECK_RV(rv, "CKA_WRAP_TEMPLATE on private key",
             CKR_ATTRIBUTE_TYPE_INVALID);
    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
                                     TMPL_CNT(pubTmpl), privTmpl,
                                     TMPL_CNT(privTmpl) - 1, &pub, &priv);
    CHECK_RV(rv, "generate key pair", CKR_OK);
    if (rv != CKR_OK)
        return;

    outer.type = CKA_UNWRAP_TEMPLATE;
    outer.pValue = NULL;
    outer.ulValueLen = 0;
    rv = funcList->C_GetAttributeValue(session, priv, &outer, 1);
    CHECK_RV(rv, "private key template", CKR_OK);
    CHECK_TRUE(outer.ulValueLen == sizeof(inner), "private key template set");
    rv = funcList->C_GetAttributeValue(session, pub, &outer, 1);
    CHECK_RV(rv, "public key has no unwrap template",
             CKR_ATTRIBUTE_TYPE_INVALID);

#ifndef WOLFPKCS11_NO_STORE
    rv = create_secret(session, genericType, 16, exportLabel,
                       sizeof(exportLabel) - 1, NULL, 0, &match);
    if (rv == CKR_OK) {
        rv = create_secret(session, genericType, 16, otherLabel,
                           sizeof(otherLabel) - 1, NULL, 0, &wrong);
    }
    CHECK_RV(rv, "create keys", CKR_OK);
    if (rv == CKR_OK) {
        outLen = sizeof(out);
        rv = funcList->C_WrapKey(session, &wrapMech, pub, match, out, &outLen);
        CHECK_RV(rv, "RSA wrap matching key", CKR_OK);
        outLen = sizeof(out);
        rv = funcList->C_WrapKey(session, &wrapMech, pub, wrong, out, &outLen);
        CHECK_RV(rv, "RSA wrap other key", CKR_KEY_HANDLE_INVALID);
    }
    funcList->C_DestroyObject(session, wrong);
    funcList->C_DestroyObject(session, match);
#else
    (void)wrapMech;
    (void)match;
    (void)wrong;
    (void)out;
    (void)outLen;
#endif
    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}
#endif

#ifndef WOLFPKCS11_NO_STORE
static void test_persistence(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_BYTE id[] = "tmpl-kek";
    CK_ATTRIBUTE inner[] = {
        { CKA_LABEL, exportLabel, sizeof(exportLabel) - 1 },
    };
    CK_ATTRIBUTE extra[] = {
        { CKA_WRAP_TEMPLATE, inner,   sizeof(inner)  },
        { CKA_ID,            id,      sizeof(id) - 1 },
        { CKA_TOKEN,         &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE find[] = {
        { CKA_ID, id, sizeof(id) - 1 },
    };
    CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE;
    CK_ULONG found = 0;
    CK_ATTRIBUTE get[1];
    CK_ATTRIBUTE outer;
    CK_BYTE label[16];
#ifdef TEST_WRAP
    CK_BYTE iv[16];
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_OBJECT_HANDLE wrong = CK_INVALID_HANDLE;
    CK_BYTE out[64];
    CK_ULONG outLen = sizeof(out);
#endif

    printf("\n--- token object templates ---\n");
    rv = create_secret(*session, genericType, 32, NULL, 0, extra,
                       TMPL_CNT(extra), &kek);
    CHECK_RV(rv, "create token KEK", CKR_OK);
    if (rv != CKR_OK)
        return;

    funcList->C_CloseSession(*session);
    funcList->C_Finalize(NULL);
    rv = initialize(&slot);
    if (rv == CKR_OK)
        rv = open_user_session(slot, session);
    CHECK_RV(rv, "reload token", CKR_OK);
    if (rv != CKR_OK)
        return;

    kek = CK_INVALID_HANDLE;
    rv = funcList->C_FindObjectsInit(*session, find, TMPL_CNT(find));
    if (rv == CKR_OK)
        rv = funcList->C_FindObjects(*session, &kek, 1, &found);
    funcList->C_FindObjectsFinal(*session);
    CHECK_TRUE(rv == CKR_OK && found == 1, "find reloaded KEK");
    if (found != 1)
        return;

    XMEMSET(get, 0, sizeof(get));
    get[0].pValue = label;
    get[0].ulValueLen = sizeof(label);
    outer.type = CKA_WRAP_TEMPLATE;
    outer.pValue = get;
    outer.ulValueLen = sizeof(get);
    rv = funcList->C_GetAttributeValue(*session, kek, &outer, 1);
    CHECK_RV(rv, "reloaded template", CKR_OK);
    CHECK_TRUE(outer.ulValueLen == sizeof(get) && get[0].type == CKA_LABEL &&
               get[0].ulValueLen == sizeof(exportLabel) - 1 &&
               XMEMCMP(label, exportLabel, sizeof(exportLabel) - 1) == 0,
               "reloaded template contents");

#ifdef TEST_WRAP
    XMEMSET(iv, 0, sizeof(iv));
    rv = create_secret(*session, aesType, 16, otherLabel,
                       sizeof(otherLabel) - 1, NULL, 0, &wrong);
    if (rv == CKR_OK) {
        rv = funcList->C_WrapKey(*session, &mech, kek, wrong, out, &outLen);
        CHECK_RV(rv, "reloaded template enforced", CKR_KEY_HANDLE_INVALID);
        funcList->C_DestroyObject(*session, wrong);
    }
#endif
    funcList->C_DestroyObject(*session, kek);
}
#endif

#ifdef TEST_TAMPER
/* Cut the template field off the object record that ends with label. */
static int strip_template(const CK_BYTE* label, size_t labelLen)
{
    static unsigned char buf[4096];
    char path[512];
    DIR* d;
    struct dirent* e;
    FILE* f;
    size_t sz;
    size_t entSz = 14 + labelLen;
    int stripped = 0;

    d = opendir(TEST_DIR);
    if (d == NULL)
        return 0;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "wp11_obj_", 9) != 0)
            continue;
        snprintf(path, sizeof(path), "%s/%s", TEST_DIR, e->d_name);
        f = fopen(path, "rb");
        if (f == NULL)
            continue;
        sz = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        if (sz < entSz + 4 || buf[sz - entSz - 4] != 0 ||
                buf[sz - entSz - 3] != 0 || buf[sz - entSz - 2] != 0 ||
                buf[sz - entSz - 1] != (unsigned char)entSz ||
                memcmp(buf + sz - labelLen, label, labelLen) != 0)
            continue;
        f = fopen(path, "wb");
        if (f == NULL)
            continue;
        if (fwrite(buf, 1, sz - entSz - 4, f) == sz - entSz - 4)
            stripped++;
        fclose(f);
    }
    closedir(d);
    return stripped;
}

static CK_ULONG find_by_id(CK_SESSION_HANDLE session, CK_BYTE* id,
                           CK_ULONG idLen, CK_OBJECT_HANDLE* obj)
{
    CK_RV rv;
    CK_ULONG found = 0;
    CK_ATTRIBUTE find[1];

    find[0].type = CKA_ID;
    find[0].pValue = id;
    find[0].ulValueLen = idLen;
    *obj = CK_INVALID_HANDLE;
    rv = funcList->C_FindObjectsInit(session, find, 1);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, obj, 1, &found);
        funcList->C_FindObjectsFinal(session);
    }
    return (rv == CKR_OK) ? found : 0;
}

static CK_RV wrap_with(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE kek,
                       CK_OBJECT_HANDLE key)
{
    CK_BYTE iv[16];
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_BYTE out[64];
    CK_ULONG outLen = sizeof(out);

    XMEMSET(iv, 0, sizeof(iv));
    return funcList->C_WrapKey(session, &mech, kek, key, out, &outLen);
}

static void test_tamper(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_BYTE id[] = "tmpl-tamper";
    CK_BYTE ctrlId[] = "tmpl-control";
    CK_BYTE tamperLabel[] = "tamper";
    CK_BYTE newPin[] = "wolfpkcs11-rekey";
    CK_ATTRIBUTE inner[] = {
        { CKA_LABEL, tamperLabel, sizeof(tamperLabel) - 1 },
    };
    CK_ATTRIBUTE ctrlInner[] = {
        { CKA_LABEL, exportLabel, sizeof(exportLabel) - 1 },
    };
    CK_ATTRIBUTE extra[] = {
        { CKA_WRAP_TEMPLATE, inner,   sizeof(inner)  },
        { CKA_ID,            id,      sizeof(id) - 1 },
        { CKA_TOKEN,         &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE ctrlExtra[] = {
        { CKA_WRAP_TEMPLATE, ctrlInner, sizeof(ctrlInner)  },
        { CKA_ID,            ctrlId,    sizeof(ctrlId) - 1 },
        { CKA_TOKEN,         &ckTrue,   sizeof(ckTrue)     },
    };
    CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE ctrl = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE match = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE other = CK_INVALID_HANDLE;
    CK_ULONG found;
    CK_RV wrapRv = CKR_OK;

    printf("\n--- stripped and re-keyed token templates ---\n");
    rv = create_secret(*session, aesType, 32, NULL, 0, extra,
                       TMPL_CNT(extra), &kek);
    if (rv == CKR_OK)
        rv = create_secret(*session, aesType, 32, NULL, 0, ctrlExtra,
                           TMPL_CNT(ctrlExtra), &ctrl);
    CHECK_RV(rv, "create token KEKs", CKR_OK);
    if (rv != CKR_OK)
        return;

    funcList->C_CloseSession(*session);
    funcList->C_Finalize(NULL);
    rv = initialize(&slot);
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, session);
    if (rv == CKR_OK)
        rv = funcList->C_SetPIN(*session, userPin, sizeof(userPin) - 1,
                                newPin, sizeof(newPin) - 1);
    if (rv == CKR_OK)
        rv = funcList->C_SetPIN(*session, newPin, sizeof(newPin) - 1,
                                userPin, sizeof(userPin) - 1);
    CHECK_RV(rv, "re-key token KEKs", CKR_OK);

    funcList->C_CloseSession(*session);
    funcList->C_Finalize(NULL);
    CHECK_TRUE(strip_template(tamperLabel, sizeof(tamperLabel) - 1) == 1,
               "strip template from store");
    rv = initialize(&slot);
    if (rv == CKR_OK)
        rv = open_user_session(slot, session);
    CHECK_RV(rv, "reload stripped token", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = create_secret(*session, aesType, 16, exportLabel,
                       sizeof(exportLabel) - 1, NULL, 0, &match);
    if (rv == CKR_OK)
        rv = create_secret(*session, aesType, 16, otherLabel,
                           sizeof(otherLabel) - 1, NULL, 0, &other);
    CHECK_RV(rv, "create keys to wrap", CKR_OK);
    if (rv != CKR_OK)
        return;

    found = find_by_id(*session, ctrlId, sizeof(ctrlId) - 1, &ctrl);
    CHECK_TRUE(found == 1, "find re-keyed KEK");
    if (found == 1) {
        rv = wrap_with(*session, ctrl, match);
        CHECK_RV(rv, "re-keyed KEK wraps", CKR_OK);
        rv = wrap_with(*session, ctrl, other);
        CHECK_RV(rv, "re-keyed KEK template enforced", CKR_KEY_HANDLE_INVALID);
        funcList->C_DestroyObject(*session, ctrl);
    }

    found = find_by_id(*session, id, sizeof(id) - 1, &kek);
    if (found == 1) {
        wrapRv = wrap_with(*session, kek, other);
        funcList->C_DestroyObject(*session, kek);
    }
    CHECK_TRUE(found == 0 || wrapRv != CKR_OK, "stripped KEK unusable");
    funcList->C_DestroyObject(*session, match);
    funcList->C_DestroyObject(*session, other);
}
#endif

static int run_test(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = initialize(&slot);
    if (rv == CKR_OK)
        rv = provision_token(slot);
    if (rv == CKR_OK)
        rv = open_user_session(slot, &session);
    CHECK_RV(rv, "open user session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    test_set_get(session);
#ifdef TEST_WRAP
    test_wrap(session);
    test_unwrap(session);
#endif
#ifdef WOLFPKCS11_CONCATENATE
    test_derive(session);
#endif
#ifdef TEST_LOGIN_RACE
    test_derive_login_race(session);
#endif
#ifdef WOLFSSL_HAVE_PRF
    test_tls_derive(session);
#endif
#ifdef WOLFPKCS11_HKDF
    test_hkdf_salt(session);
#endif
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    test_key_pair(session);
#endif
#ifndef WOLFPKCS11_NO_STORE
    test_persistence(slot, &session);
#endif
#ifdef TEST_TAMPER
    test_tamper(slot, &session);
#endif

out:
    if (session != CK_INVALID_HANDLE)
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

    printf("=== wolfPKCS11 attribute-array template test ===\n");
    run_test();
    return pkcs11_test_summary();
}
