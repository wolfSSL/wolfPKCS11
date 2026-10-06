/* key_material_update_test.c
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
 * Key material and certificate values are fixed once an object exists, and
 * what the token persists matches the live object.
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

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/key_material_update_test"

static CK_SLOT_ID slot = 0;
static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "key-material-update";

static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue  = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static CK_RV token_setup(void)
{
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE soSession = 0;
    unsigned char label[32];
    CK_RV rv;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_OK && slotCount == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK) {
        slot = slotList[0];
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &soSession);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(soSession, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
        if (rv == CKR_OK) {
            rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                     (CK_ULONG)XSTRLEN(userPin));
            funcList->C_Logout(soSession);
        }
        funcList->C_CloseSession(soSession);
    }
    return rv;
}

static CK_RV open_session(CK_SESSION_HANDLE* session, int login)
{
    CK_RV rv;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, session);
    if (rv == CKR_OK && login) {
        rv = funcList->C_Login(*session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    return rv;
}

#ifndef WOLFPKCS11_NO_STORE
/* Finalize so token objects are written out, then load them again. */
static CK_RV reload_token(CK_SESSION_HANDLE* session, int login)
{
    CK_C_INITIALIZE_ARGS args;
    CK_RV rv;

    funcList->C_CloseSession(*session);
    *session = 0;
    funcList->C_Finalize(NULL);

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = open_session(session, login);
    return rv;
}

static CK_OBJECT_HANDLE find_by_label(CK_SESSION_HANDLE session,
                                      const char* label)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_LABEL, (void*)label, (CK_ULONG)XSTRLEN(label) },
    };

    rv = funcList->C_FindObjectsInit(session, tmpl, 1);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, &obj, 1, &count);
        funcList->C_FindObjectsFinal(session);
    }
    if (rv != CKR_OK || count != 1)
        obj = CK_INVALID_HANDLE;
    return obj;
}
#endif

/* Read an attribute value and compare it with the expected bytes. */
static int attr_equals(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                       CK_ATTRIBUTE_TYPE type, const byte* expect,
                       CK_ULONG expectLen)
{
    CK_RV rv;
    byte buf[512];
    CK_ATTRIBUTE attr;

    attr.type = type;
    attr.pValue = buf;
    attr.ulValueLen = sizeof(buf);
    rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    return rv == CKR_OK && attr.ulValueLen == expectLen &&
           XMEMCMP(buf, expect, expectLen) == 0;
}

static void destroy_obj(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* obj)
{
    if (*obj != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, *obj);
        *obj = CK_INVALID_HANDLE;
    }
}

#ifndef NO_RSA
/* A token public key's modulus cannot be replaced and the persisted key
 * matches the live key. */
static void check_token_modulus_fixed(CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE rsa = CK_INVALID_HANDLE;
    static const char rsaLabel[] = "kmu-token-rsa";
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE rsaType = CKK_RSA;
    byte newMod[sizeof(rsa_2048_modulus)];
    byte liveMod[sizeof(rsa_2048_modulus) + 16];
    CK_ATTRIBUTE liveAttr = { CKA_MODULUS, liveMod, sizeof(liveMod) };
    CK_ATTRIBUTE rsaTmpl[] = {
        { CKA_CLASS,           &pubClass,        sizeof(pubClass)         },
        { CKA_KEY_TYPE,        &rsaType,         sizeof(rsaType)          },
        { CKA_TOKEN,           &ckTrue,          sizeof(ckTrue)           },
        { CKA_PRIVATE,         &ckFalse,         sizeof(ckFalse)          },
        { CKA_LABEL,           (void*)rsaLabel,  sizeof(rsaLabel) - 1     },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };
    CK_ATTRIBUTE setMod[] = { { CKA_MODULUS, newMod, sizeof(newMod) } };

    XMEMCPY(newMod, rsa_2048_modulus, sizeof(newMod));
    newMod[sizeof(newMod) - 1] ^= 0x02;
    rv = funcList->C_CreateObject(*session, rsaTmpl,
                                  sizeof(rsaTmpl) / sizeof(*rsaTmpl), &rsa);
    CHECK_RV(rv, "create token RSA public key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SetAttributeValue(*session, rsa, setMod, 1);
    CHECK_RV(rv, "set modulus on existing key", CKR_ATTRIBUTE_READ_ONLY);
    rv = funcList->C_GetAttributeValue(*session, rsa, &liveAttr, 1);
    CHECK_RV(rv, "read live modulus", CKR_OK);
    CHECK_TRUE(liveAttr.ulValueLen == sizeof(rsa_2048_modulus) &&
               XMEMCMP(liveMod, rsa_2048_modulus,
                       sizeof(rsa_2048_modulus)) == 0,
               "live modulus unchanged");

#ifndef WOLFPKCS11_NO_STORE
    /* Token objects are decoded at login. */
    rv = reload_token(session, 1);
    CHECK_RV(rv, "reload token", CKR_OK);
    if (rv != CKR_OK)
        return;
    rsa = find_by_label(*session, rsaLabel);
    CHECK_TRUE(rsa != CK_INVALID_HANDLE &&
               attr_equals(*session, rsa, CKA_MODULUS, liveMod,
                           liveAttr.ulValueLen),
               "persisted modulus matches live modulus");
#endif
    destroy_obj(*session, &rsa);
}
#endif

/* A token secret key's value cannot be replaced directly or through a copy
 * template, and C_CopyObject still carries the key material over. */
static void check_token_secret_fixed(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    static const char keyLabel[] = "kmu-token-key";
    static const char copyLabel[] = "kmu-token-key-copy";
    byte origVal[16];
    byte newVal[16];
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,       &secretClass,      sizeof(secretClass)   },
        { CKA_KEY_TYPE,    &genericType,      sizeof(genericType)   },
        { CKA_TOKEN,       &ckTrue,           sizeof(ckTrue)        },
        { CKA_SENSITIVE,   &ckFalse,          sizeof(ckFalse)       },
        { CKA_EXTRACTABLE, &ckTrue,           sizeof(ckTrue)        },
        { CKA_LABEL,       (void*)keyLabel,   sizeof(keyLabel) - 1  },
        { CKA_VALUE,       origVal,           sizeof(origVal)       },
    };
    CK_ATTRIBUTE setValue[] = { { CKA_VALUE, newVal, sizeof(newVal) } };
    CK_ATTRIBUTE copyWithValue[] = {
        { CKA_LABEL, (void*)copyLabel, sizeof(copyLabel) - 1 },
        { CKA_VALUE, newVal,           sizeof(newVal)        },
    };
    CK_ATTRIBUTE copyTmpl[] = {
        { CKA_LABEL, (void*)copyLabel, sizeof(copyLabel) - 1 },
    };

    XMEMSET(origVal, 0x11, sizeof(origVal));
    XMEMSET(newVal, 0x22, sizeof(newVal));

    rv = funcList->C_CreateObject(session, keyTmpl,
                                  sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    CHECK_RV(rv, "create token secret key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SetAttributeValue(session, key, setValue, 1);
    CHECK_RV(rv, "set key value on existing key", CKR_ATTRIBUTE_READ_ONLY);
    CHECK_TRUE(attr_equals(session, key, CKA_VALUE, origVal, sizeof(origVal)),
               "live key value unchanged");

    rv = funcList->C_CopyObject(session, key, copyWithValue, 2, &copy);
    CHECK_RV(rv, "copy with a new key value", CKR_ATTRIBUTE_READ_ONLY);
    destroy_obj(session, &copy);

    rv = funcList->C_CopyObject(session, key, copyTmpl, 1, &copy);
    CHECK_RV(rv, "copy token secret key", CKR_OK);
    CHECK_TRUE(attr_equals(session, copy, CKA_VALUE, origVal, sizeof(origVal)),
               "copy carries the key value");

    destroy_obj(session, &copy);
    destroy_obj(session, &key);
}

static void test_token_key_value_fixed(CK_SESSION_HANDLE* session)
{
    CK_RV rv;

#ifndef NO_RSA
    check_token_modulus_fixed(session);
#endif
    rv = funcList->C_Login(*session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                           (CK_ULONG)XSTRLEN(userPin));
    if (rv == CKR_USER_ALREADY_LOGGED_IN)
        rv = CKR_OK;
    CHECK_RV(rv, "login user", CKR_OK);
    if (rv == CKR_OK)
        check_token_secret_fixed(*session);
}

/* A rejected secret key update leaves the existing key usable. */
static void test_rejected_secret_update_keeps_key(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte origVal[16];
    byte newVal[16];
    CK_ULONG shortLen = 8;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType, sizeof(genericType) },
        { CKA_TOKEN,       &ckFalse,     sizeof(ckFalse)     },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,       origVal,      sizeof(origVal)     },
    };
    CK_ATTRIBUTE badUpdate[] = {
        { CKA_VALUE_LEN, &shortLen, sizeof(shortLen) },
        { CKA_VALUE,     newVal,    sizeof(newVal)   },
    };
#ifndef NO_AES
    CK_KEY_TYPE aesType = CKK_AES;
    CK_ULONG badAesLen = 17;
    CK_ATTRIBUTE badAesLenTmpl[] = {
        { CKA_VALUE_LEN, &badAesLen, sizeof(badAesLen) },
    };
#endif

    XMEMSET(origVal, 0x33, sizeof(origVal));
    XMEMSET(newVal, 0x44, sizeof(newVal));

    rv = funcList->C_CreateObject(session, keyTmpl,
                                  sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    CHECK_RV(rv, "create secret key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, key, badUpdate, 2);
        CHECK_RV(rv, "inconsistent key update rejected",
                 CKR_ATTRIBUTE_READ_ONLY);
        CHECK_TRUE(attr_equals(session, key, CKA_VALUE, origVal,
                               sizeof(origVal)),
                   "key kept after rejected update");
    }
    destroy_obj(session, &key);

#ifndef NO_AES
    keyTmpl[1].pValue = &aesType;
    rv = funcList->C_CreateObject(session, keyTmpl,
                                  sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    CHECK_RV(rv, "create AES key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, key, badAesLenTmpl, 1);
        CHECK_RV(rv, "invalid AES key length rejected",
                 CKR_ATTRIBUTE_READ_ONLY);
        CHECK_TRUE(attr_equals(session, key, CKA_VALUE, origVal,
                               sizeof(origVal)),
                   "AES key kept after rejected length");
    }
    destroy_obj(session, &key);
#endif
}

#ifndef NO_DH
/* A DH private value cannot be replaced once the key exists. */
static void test_dh_private_value_fixed(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE dhType = CKK_DH;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,       &privClass,     sizeof(privClass)      },
        { CKA_KEY_TYPE,    &dhType,        sizeof(dhType)         },
        { CKA_TOKEN,       &ckFalse,       sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,       sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,        sizeof(ckTrue)         },
        { CKA_PRIME,       dh_ffdhe2048_p, sizeof(dh_ffdhe2048_p) },
        { CKA_BASE,        dh_ffdhe2048_g, sizeof(dh_ffdhe2048_g) },
        { CKA_VALUE,       dh_2048_priv,   sizeof(dh_2048_priv)   },
    };
    CK_ATTRIBUTE shorterValue[] = {
        { CKA_VALUE, dh_2048_priv, sizeof(dh_2048_priv) / 2 },
    };

    rv = funcList->C_CreateObject(session, keyTmpl,
                                  sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    CHECK_RV(rv, "create DH private key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, key, shorterValue, 1);
        CHECK_RV(rv, "set shorter DH private value", CKR_ATTRIBUTE_READ_ONLY);
        CHECK_TRUE(attr_equals(session, key, CKA_VALUE, dh_2048_priv,
                               sizeof(dh_2048_priv)),
                   "DH private value unchanged");
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

    rv = token_setup();
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK) {
        rv = open_session(&session, 0);
        CHECK_RV(rv, "open session", CKR_OK);
    }
    if (rv == CKR_OK) {
        test_token_key_value_fixed(&session);
        test_rejected_secret_update_keeps_key(session);
#ifndef NO_DH
        test_dh_private_value_fixed(session);
#endif
    }

    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
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

    printf("=== wolfPKCS11 key material update test ===\n");
    run_test();
    return pkcs11_test_summary();
}
