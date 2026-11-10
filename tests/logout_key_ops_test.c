/* logout_key_ops_test.c
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
 * Checks that logging out ends the operations keyed by private keys and that
 * a logout between the key check and the key read leaves no key in use.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>

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

#define TEST_DIR "./store/logout_key_ops_test"

#if !defined(WOLFPKCS11_NO_STORE) && !defined(NO_AES)

static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "logout-key-ops";
static unsigned char keyValue[16] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f
};
static unsigned char data[32] = { 0 };

static CK_RV token_setup(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE soSession = CK_INVALID_HANDLE;
    unsigned char label[32];

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_OK && slotCount == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK) {
        *slot = slotList[0];
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(*slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(*slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &soSession);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(soSession, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
        funcList->C_Logout(soSession);
    }
    if (soSession != CK_INVALID_HANDLE)
        funcList->C_CloseSession(soSession);
    return rv;
}

static CK_RV open_session(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    return funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                   NULL, NULL, session);
}

static CK_RV login(CK_SESSION_HANDLE session)
{
    return funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                             (CK_ULONG)XSTRLEN(userPin));
}

static CK_RV create_key(CK_SESSION_HANDLE session, CK_KEY_TYPE keyType,
                        CK_BBOOL onToken, CK_BBOOL priv,
                        CK_OBJECT_HANDLE* key)
{
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE,    &keyType,  sizeof(keyType)  },
        { CKA_TOKEN,       &onToken,  sizeof(onToken)  },
        { CKA_PRIVATE,     &priv,     sizeof(priv)     },
        { CKA_SENSITIVE,   &no,       sizeof(no)       },
        { CKA_EXTRACTABLE, &yes,      sizeof(yes)      },
        { CKA_ENCRYPT,     &yes,      sizeof(yes)      },
        { CKA_SIGN,        &yes,      sizeof(yes)      },
        { CKA_WRAP,        &yes,      sizeof(yes)      },
        { CKA_VALUE,       keyValue,  sizeof(keyValue) },
    };

    return funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), key);
}

typedef struct KeyOp {
    const char* name;
    CK_MECHANISM_TYPE mech;
    void* param;
    CK_ULONG paramLen;
    CK_KEY_TYPE keyType;
    int sign;
} KeyOp;

static CK_RV init_op(CK_SESSION_HANDLE session, const KeyOp* op,
                     CK_OBJECT_HANDLE key)
{
    CK_MECHANISM mech;

    mech.mechanism = op->mech;
    mech.pParameter = op->param;
    mech.ulParameterLen = op->paramLen;
    if (op->sign)
        return funcList->C_SignInit(session, &mech, key);
    return funcList->C_EncryptInit(session, &mech, key);
}

static CK_RV continue_op(CK_SESSION_HANDLE session, const KeyOp* op)
{
    unsigned char out[sizeof(data)];
    CK_ULONG outLen = sizeof(out);

    if (op->sign)
        return funcList->C_SignUpdate(session, data, sizeof(data));
    return funcList->C_EncryptUpdate(session, data, sizeof(data), out,
                                     &outLen);
}

static CK_RV start_op(CK_SESSION_HANDLE session, const KeyOp* op,
                      CK_OBJECT_HANDLE key)
{
    CK_RV rv;

    rv = init_op(session, op, key);
    if (rv == CKR_OK)
        rv = continue_op(session, op);
    return rv;
}

#ifdef HAVE_AES_CBC
static unsigned char iv[16] = { 0 };
#endif
#ifdef HAVE_AESCTR
static CK_AES_CTR_PARAMS ctrParams = { 128, { 0 } };
#endif

static const KeyOp keyOps[] = {
#ifdef HAVE_AES_CBC
    { "AES-CBC", CKM_AES_CBC, iv, sizeof(iv), CKK_AES, 0 },
#endif
#ifdef HAVE_AESCTR
    { "AES-CTR", CKM_AES_CTR, &ctrParams, sizeof(ctrParams), CKK_AES, 0 },
#endif
#if !defined(NO_HMAC) && !defined(NO_SHA256)
    { "HMAC", CKM_SHA256_HMAC, NULL, 0, CKK_GENERIC_SECRET, 1 },
#endif
#ifdef HAVE_AESCMAC
    { "AES-CMAC", CKM_AES_CMAC, NULL, 0, CKK_AES, 1 },
#endif
    { NULL, 0, NULL, 0, 0, 0 }
};

#define KEY_OP_CNT (sizeof(keyOps) / sizeof(*keyOps) - 1)

/* Each op runs on its own session with a new key, destroyed first when
 * asked; logout ends them all. */
static void ops_end_at_logout(CK_SLOT_ID slot, CK_BBOOL onToken, CK_BBOOL priv,
                              CK_BBOOL destroy, const char* what)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE opSession[KEY_OP_CNT + 1];
    CK_OBJECT_HANDLE key;
    char msg[96];
    size_t i;

    printf("--- logout ends operations on %s ---\n", what);
    for (i = 0; i < KEY_OP_CNT; i++)
        opSession[i] = CK_INVALID_HANDLE;
    rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session);
    for (i = 0; rv == CKR_OK && i < KEY_OP_CNT; i++) {
        rv = open_session(slot, &opSession[i]);
        if (rv == CKR_OK)
            rv = create_key(session, keyOps[i].keyType, onToken, priv, &key);
        if (rv == CKR_OK)
            rv = start_op(opSession[i], &keyOps[i], key);
        if (rv == CKR_OK && destroy)
            rv = funcList->C_DestroyObject(session, key);
        snprintf(msg, sizeof(msg), "%s started on %s", keyOps[i].name, what);
        CHECK_RV(rv, msg, CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Logout(session);
        CHECK_RV(rv, "C_Logout", CKR_OK);
    }
    for (i = 0; rv == CKR_OK && i < KEY_OP_CNT; i++) {
        snprintf(msg, sizeof(msg), "%s ended by logout", keyOps[i].name);
        CHECK_RV(continue_op(opSession[i], &keyOps[i]), msg,
                 CKR_OPERATION_NOT_INITIALIZED);
    }
    for (i = 0; i < KEY_OP_CNT; i++) {
        if (opSession[i] != CK_INVALID_HANDLE)
            funcList->C_CloseSession(opSession[i]);
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}

#ifdef DEBUG_WOLFPKCS11

#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Test_SetKeyDecodedHook(void (*hook)(void));
extern void WP11_Test_SetDiscardHook(void (*hook)(void));
extern void WP11_Test_SetGetObjectHook(void (*hook)(void));
#ifdef __cplusplus
}
#endif

static CK_SESSION_HANDLE hookSession = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE hookKey = CK_INVALID_HANDLE;
static int hookCountdown = 0;
static CK_RV hookRv = CKR_GENERAL_ERROR;

/* Log out, or destroy hookKey, on the chosen key check after it passed. */
static void hook_logout(void)
{
    if (hookCountdown > 0) {
        hookCountdown--;
        if (hookCountdown == 0 && hookKey != CK_INVALID_HANDLE)
            hookRv = funcList->C_DestroyObject(hookSession, hookKey);
        else if (hookCountdown == 0)
            hookRv = funcList->C_Logout(hookSession);
    }
}

static void arm_logout(void (*setHook)(void (*hook)(void)),
                       CK_SESSION_HANDLE session, int check)
{
    hookSession = session;
    hookKey = CK_INVALID_HANDLE;
    hookCountdown = check;
    hookRv = CKR_GENERAL_ERROR;
    setHook(hook_logout);
}

/* A key destroyed after the key check must not start the operation. */
static void destroy_during_init(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;
    char msg[96];
    size_t i;

    printf("--- destroy between key check and init ---\n");
    rv = open_session(slot, &session);
    for (i = 0; rv == CKR_OK && i < KEY_OP_CNT; i++) {
        rv = create_key(session, keyOps[i].keyType, CK_FALSE, CK_FALSE, &key);
        CHECK_RV(rv, "create session key", CKR_OK);
        if (rv != CKR_OK)
            break;
        arm_logout(WP11_Test_SetKeyDecodedHook, session, 1);
        hookKey = key;
        rv = init_op(session, &keyOps[i], key);
        WP11_Test_SetKeyDecodedHook(NULL);
        snprintf(msg, sizeof(msg), "C_DestroyObject inside %s init",
                 keyOps[i].name);
        CHECK_RV(hookRv, msg, CKR_OK);
        snprintf(msg, sizeof(msg), "%s init refused after the destroy",
                 keyOps[i].name);
        CHECK_TRUE(rv != CKR_OK, msg);
        snprintf(msg, sizeof(msg), "%s not left running", keyOps[i].name);
        CHECK_RV(continue_op(session, &keyOps[i]), msg,
                 CKR_OPERATION_NOT_INITIALIZED);
        rv = CKR_OK;
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}

/* A logout after the key check must not leave the operation running. */
static void logout_during_init(CK_SLOT_ID slot, CK_BBOOL onToken,
                               const char* what)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;
    char msg[96];
    size_t i;

    printf("--- logout between key check and init on %s ---\n", what);
    rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = open_session(slot, &other);
    for (i = 0; rv == CKR_OK && i < KEY_OP_CNT; i++) {
        rv = login(other);
        if (rv == CKR_OK) {
            rv = create_key(other, keyOps[i].keyType, onToken, CK_TRUE, &key);
        }
        CHECK_RV(rv, "log in and create private key", CKR_OK);
        if (rv != CKR_OK)
            break;
        arm_logout(WP11_Test_SetKeyDecodedHook, other, 1);
        rv = init_op(session, &keyOps[i], key);
        WP11_Test_SetKeyDecodedHook(NULL);
        snprintf(msg, sizeof(msg), "C_Logout inside %s init",
                  keyOps[i].name);
        CHECK_RV(hookRv, msg, CKR_OK);
        snprintf(msg, sizeof(msg), "%s init refused after the logout",
                  keyOps[i].name);
        CHECK_RV(rv, msg, CKR_FUNCTION_FAILED);
        snprintf(msg, sizeof(msg), "%s not left running", keyOps[i].name);
        CHECK_RV(continue_op(session, &keyOps[i]), msg,
                 CKR_OPERATION_NOT_INITIALIZED);
        rv = CKR_OK;
    }
    if (other != CK_INVALID_HANDLE)
        funcList->C_CloseSession(other);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}

/* A logout between the unlink and the discard of a destroyed key ends its
 * operations. */
static void logout_during_destroy(CK_SLOT_ID slot, CK_BBOOL priv,
                                  const char* what)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE opSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;
    char msg[96];
    size_t i;

    printf("--- logout while destroying %s ---\n", what);
    rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = open_session(slot, &opSession);
    for (i = 0; rv == CKR_OK && i < KEY_OP_CNT; i++) {
        rv = login(session);
        if (rv == CKR_OK)
            rv = create_key(session, keyOps[i].keyType, CK_TRUE, priv, &key);
        if (rv == CKR_OK)
            rv = start_op(opSession, &keyOps[i], key);
        snprintf(msg, sizeof(msg), "%s started", keyOps[i].name);
        CHECK_RV(rv, msg, CKR_OK);
        if (rv != CKR_OK)
            break;
        arm_logout(WP11_Test_SetDiscardHook, session, 1);
        rv = funcList->C_DestroyObject(session, key);
        WP11_Test_SetDiscardHook(NULL);
        CHECK_RV(hookRv, "C_Logout inside C_DestroyObject", CKR_OK);
        CHECK_RV(rv, "C_DestroyObject", CKR_OK);
        snprintf(msg, sizeof(msg), "%s ended by logout", keyOps[i].name);
        CHECK_RV(continue_op(opSession, &keyOps[i]), msg,
                 CKR_OPERATION_NOT_INITIALIZED);
        rv = CKR_OK;
    }
    if (opSession != CK_INVALID_HANDLE)
        funcList->C_CloseSession(opSession);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}

#ifdef HAVE_ECC
/* A logout after C_Sign read its key must not report a zero length. */
static void logout_during_sign_len(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_BBOOL yes = CK_TRUE;
    CK_MECHANISM genMech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VERIFY,    &yes,            sizeof(yes)             },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &yes, sizeof(yes) },
        { CKA_PRIVATE, &yes, sizeof(yes) },
        { CKA_SIGN,    &yes, sizeof(yes) },
    };
    CK_ULONG sigLen = 0;

    printf("--- logout during a signature length query ---\n");
    rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = open_session(slot, &other);
    if (rv == CKR_OK)
        rv = login(other);
    if (rv == CKR_OK) {
        rv = funcList->C_GenerateKeyPair(other, &genMech, pubTmpl,
                sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
                sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
    }
    if (rv == CKR_OK)
        rv = funcList->C_SignInit(session, &mech, priv);
    CHECK_RV(rv, "ECDSA sign started", CKR_OK);
    if (rv == CKR_OK) {
        arm_logout(WP11_Test_SetGetObjectHook, other, 1);
        rv = funcList->C_Sign(session, data, sizeof(data), NULL, &sigLen);
        WP11_Test_SetGetObjectHook(NULL);
        CHECK_RV(hookRv, "C_Logout inside C_Sign", CKR_OK);
        CHECK_TRUE(rv != CKR_OK || sigLen != 0, "no zero signature length");
    }
    if (other != CK_INVALID_HANDLE)
        funcList->C_CloseSession(other);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}
#endif

#ifdef HAVE_AES_KEYWRAP
/* A logout after the target key check must not wrap the scrubbed value. */
static void logout_during_wrap(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE wrapKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_AES_KEY_WRAP, NULL, 0 };
    unsigned char wrapped[64];
    CK_ULONG wrappedLen = sizeof(wrapped);

    printf("--- logout between key check and wrap ---\n");
    rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session);
    if (rv == CKR_OK)
        rv = create_key(session, CKK_AES, CK_FALSE, CK_FALSE, &wrapKey);
    if (rv == CKR_OK)
        rv = create_key(session, CKK_GENERIC_SECRET, CK_TRUE, CK_TRUE, &key);
    CHECK_RV(rv, "create wrapping key and private token key", CKR_OK);
    if (rv == CKR_OK) {
        /* The wrapping key is checked first, the wrapped key second. */
        arm_logout(WP11_Test_SetKeyDecodedHook, session, 2);
        rv = funcList->C_WrapKey(session, &mech, wrapKey, key, wrapped,
                                 &wrappedLen);
        WP11_Test_SetKeyDecodedHook(NULL);
        CHECK_RV(hookRv, "C_Logout inside C_WrapKey", CKR_OK);
        CHECK_TRUE(rv != CKR_OK, "scrubbed key not wrapped");
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}
#endif

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
/* A logout after the wrapping key check must not report a zero length. */
static void logout_during_wrap_len(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_BBOOL yes = CK_TRUE;
    CK_ULONG bits = 2048;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 };
    CK_MECHANISM genMech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_MODULUS_BITS,    &bits, sizeof(bits) },
        { CKA_PUBLIC_EXPONENT, exp,   sizeof(exp)  },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &yes, sizeof(yes) },
        { CKA_PRIVATE, &yes, sizeof(yes) },
        { CKA_WRAP,    &yes, sizeof(yes) },
    };
    CK_ULONG wrappedLen = 0;

    printf("--- logout between key check and wrap length ---\n");
    rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session);
    if (rv == CKR_OK) {
        rv = funcList->C_GenerateKeyPair(session, &genMech, pubTmpl,
                sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
                sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
    }
    if (rv == CKR_OK)
        rv = create_key(session, CKK_AES, CK_FALSE, CK_FALSE, &key);
    CHECK_RV(rv, "create RSA wrapping key and session key", CKR_OK);
    if (rv == CKR_OK) {
        arm_logout(WP11_Test_SetKeyDecodedHook, session, 1);
        rv = funcList->C_WrapKey(session, &mech, priv, key, NULL,
                                 &wrappedLen);
        WP11_Test_SetKeyDecodedHook(NULL);
        CHECK_RV(hookRv, "C_Logout inside C_WrapKey", CKR_OK);
        CHECK_TRUE(rv != CKR_OK || wrappedLen != 0,
                   "no zero wrapped key length");
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}
#endif
#endif /* DEBUG_WOLFPKCS11 */

int main(int argc, char* argv[])
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;

    (void)argc;
    (void)argv;
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 logout key operations test ===\n");
    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv == CKR_OK) {
        rv = token_setup(&slot);
        CHECK_RV(rv, "token setup", CKR_OK);
    }
    if (rv == CKR_OK && KEY_OP_CNT > 0) {
        ops_end_at_logout(slot, CK_TRUE, CK_TRUE, CK_FALSE,
                          "private token keys");
#ifndef WOLFPKCS11_NSS
        ops_end_at_logout(slot, CK_FALSE, CK_TRUE, CK_FALSE,
                          "private session keys");
#endif
        ops_end_at_logout(slot, CK_FALSE, CK_TRUE, CK_TRUE,
                          "destroyed private keys");
        ops_end_at_logout(slot, CK_TRUE, CK_FALSE, CK_TRUE,
                          "destroyed public token keys");
#ifdef DEBUG_WOLFPKCS11
        logout_during_init(slot, CK_TRUE, "private token keys");
#ifndef WOLFPKCS11_NSS
        logout_during_init(slot, CK_FALSE, "private session keys");
#endif
        destroy_during_init(slot);
        logout_during_destroy(slot, CK_TRUE, "private token keys");
        logout_during_destroy(slot, CK_FALSE, "public token keys");
#endif
    }
#if defined(DEBUG_WOLFPKCS11) && defined(HAVE_AES_KEYWRAP)
    if (rv == CKR_OK)
        logout_during_wrap(slot);
#endif
#if defined(DEBUG_WOLFPKCS11) && defined(HAVE_ECC)
    if (rv == CKR_OK)
        logout_during_sign_len(slot);
#endif
#if defined(DEBUG_WOLFPKCS11) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    if (rv == CKR_OK)
        logout_during_wrap_len(slot);
#endif
    if (funcList != NULL)
        funcList->C_Finalize(NULL);
    pkcs11_unload();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("Needs the token store and AES, skipping test\n");
    return 77;
}

#endif
