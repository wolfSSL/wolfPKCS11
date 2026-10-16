/* object_handle_limit_test.c
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
 * Regression test for running out of object ids.
 *
 * An object handle is the object id with the onToken flag in bit 28. Ids are
 * never reused. Once an id passed 28 bits it spilled into the flag: a session
 * object got the handle of a token object, so reading or destroying it acted
 * on the token object, and closing the session freed an object that was still
 * on the session list. Object creation must fail once the ids are used up
 * instead, and a token that has used every id must still load. A stored
 * counter that is out of range, as a token written by an older version can
 * read back with TPM storage, must be replaced by one above the ids of the
 * token's objects.
 *
 * Token objects and session objects have separate counters. The token counter
 * is stored with the token, while the session counter starts again on each
 * C_Initialize. Running out of one must not stop objects of the other kind
 * from being created.
 *
 * Reaching the limit through the public API takes hundreds of millions of
 * objects, so this test uses the DEBUG_WOLFPKCS11-only hook
 * WP11_Test_SetNextObjId() to start the counters just below it.
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

#define TEST_DIR "./store/object_handle_limit_test"

#ifdef DEBUG_WOLFPKCS11

/* DEBUG_WOLFPKCS11-only test hook exported by libwolfpkcs11, with C linkage
 * as in wolfpkcs11/internal.h. */
#ifdef __cplusplus
extern "C" {
#endif
extern int WP11_Test_SetNextObjId(CK_SLOT_ID slotId, int onToken,
    int nextObjId);
#ifdef __cplusplus
}
#endif

/* Mirror OBJ_ID_MAX and the onToken handle flag in src/internal.c. */
#define OBJ_ID_MAX          0x0fffffffUL
#define HANDLE_ON_TOKEN     0x10000000UL

static CK_SLOT_ID slot = 0;
static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "object-handle-limit";

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
    if (rv != CKR_OK)
        return rv;
    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv != CKR_OK)
        return rv;
    if (slotCount == 0)
        return CKR_TOKEN_NOT_PRESENT;
    slot = slotList[0];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin), label);
    if (rv != CKR_OK)
        return rv;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &soSession);
    if (rv != CKR_OK)
        return rv;
    rv = funcList->C_Login(soSession, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                           (CK_ULONG)XSTRLEN(soPin));
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
    }
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    return rv;
}

static CK_RV open_user_session(CK_SESSION_HANDLE* session)
{
    CK_RV rv;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(*session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    return rv;
}

static CK_RV create_data(CK_SESSION_HANDLE session, CK_BBOOL onToken,
                         const char* label, CK_OBJECT_HANDLE* obj)
{
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass,    sizeof(dataClass)          },
        { CKA_TOKEN,   &onToken,      sizeof(onToken)            },
        { CKA_PRIVATE, &ckFalse,      sizeof(ckFalse)            },
        { CKA_LABEL,   (void*)label,  (CK_ULONG)XSTRLEN(label)   },
    };

    *obj = CK_INVALID_HANDLE;
    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), obj);
}

/* Check that a handle names the object with the expected label. */
static void check_label(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                        const char* expect, const char* name)
{
    CK_RV rv;
    char buf[64];
    CK_ATTRIBUTE attr = { CKA_LABEL, buf, sizeof(buf) };

    rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    CHECK_RV(rv, name, CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(attr.ulValueLen == XSTRLEN(expect) &&
                   XMEMCMP(buf, expect, attr.ulValueLen) == 0, name);
    }
}

static CK_ULONG count_objects(CK_SESSION_HANDLE session, CK_BBOOL onToken)
{
    CK_ATTRIBUTE tmpl = { CKA_TOKEN, &onToken, sizeof(onToken) };
    CK_OBJECT_HANDLE found[8];
    CK_ULONG cnt = 0;

    if (funcList->C_FindObjectsInit(session, &tmpl, 1) != CKR_OK)
        return (CK_ULONG)-1;
    if (funcList->C_FindObjects(session, found,
            sizeof(found) / sizeof(*found), &cnt) != CKR_OK) {
        cnt = (CK_ULONG)-1;
    }
    funcList->C_FindObjectsFinal(session);
    return cnt;
}

#ifdef HAVE_ECC
static CK_RV gen_keypair(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* pub,
                         CK_OBJECT_HANDLE* priv)
{
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
    };

    *pub = CK_INVALID_HANDLE;
    *priv = CK_INVALID_HANDLE;
    return funcList->C_GenerateKeyPair(session, &mech,
               pubTmpl, sizeof(pubTmpl) / sizeof(*pubTmpl),
               privTmpl, sizeof(privTmpl) / sizeof(*privTmpl), pub, priv);
}
#endif

#ifndef WOLFPKCS11_NO_STORE
static CK_RV reinitialize(void)
{
    CK_C_INITIALIZE_ARGS args;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    return funcList->C_Initialize(&args);
}

/* A token that has used every id must still load, with the session ids
 * available again. A stored counter that is out of range must be replaced by
 * one above the ids of the token's objects. */
static void reload_test(CK_OBJECT_HANDLE tokFirst, CK_OBJECT_HANDLE tokLast)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE obj;
    unsigned char label[32];

    rv = reinitialize();
    CHECK_RV(rv, "reload token with every token id used", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = open_user_session(&session);
    CHECK_RV(rv, "open user session after reload", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(count_objects(session, CK_TRUE) == 2,
                   "token objects after reload");
        check_label(session, tokLast, "token-last",
                    "last token object label after reload");
        rv = create_data(session, CK_TRUE, "token-over", &obj);
        CHECK_RV(rv, "token object after reload fails", CKR_FUNCTION_FAILED);
        rv = create_data(session, CK_FALSE, "session-reload", &obj);
        CHECK_RV(rv, "session object after reload", CKR_OK);
        CHECK_TRUE((obj & HANDLE_ON_TOKEN) == 0,
                   "session object after reload has no token flag");

        /* Destroying a token object stores the token, here with a counter
         * that is out of range. Only the first token object is left. */
        CHECK_TRUE(WP11_Test_SetNextObjId(slot, 1, -1) == 0,
                   "set next token object id out of range");
        rv = funcList->C_DestroyObject(session, tokLast);
        CHECK_RV(rv, "store token with counter out of range", CKR_OK);
    }
    funcList->C_CloseSession(session);
    session = 0;
    funcList->C_Finalize(NULL);

    rv = reinitialize();
    CHECK_RV(rv, "load token with counter out of range", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = open_user_session(&session);
    CHECK_RV(rv, "open user session after second reload", CKR_OK);
    if (rv == CKR_OK) {
        rv = create_data(session, CK_TRUE, "token-next", &obj);
        CHECK_RV(rv, "token object after counter recovered", CKR_OK);
        CHECK_TRUE(obj == tokFirst + 1,
                   "token object id follows the stored object's id");
        check_label(session, tokFirst, "token-first",
                    "first token object label after second reload");
        check_label(session, obj, "token-next", "new token object label");
        funcList->C_CloseSession(session);
    }

    /* Reset the token so a run that shares its storage starts clean. */
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin), label);
    CHECK_RV(rv, "reset token", CKR_OK);
    funcList->C_Finalize(NULL);
}
#endif

static void run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE tokFirst = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE tokLast = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE sessFirst = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE sessLast = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE over = CK_INVALID_HANDLE;
#ifdef HAVE_ECC
    CK_OBJECT_HANDLE pub;
    CK_OBJECT_HANDLE priv;
#endif

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = token_setup();
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK) {
        rv = open_user_session(&session);
        CHECK_RV(rv, "open user session", CKR_OK);
    }
    if (rv != CKR_OK) {
        funcList->C_Finalize(NULL);
        pkcs11_unload();
        return;
    }

    rv = create_data(session, CK_TRUE, "token-first", &tokFirst);
    CHECK_RV(rv, "create first token object", CKR_OK);
    CHECK_TRUE((tokFirst & HANDLE_ON_TOKEN) != 0,
               "first token object handle has the token flag");
#ifdef HAVE_ECC
    /* Control for the rollback check below. */
    rv = gen_keypair(session, &pub, &priv);
    CHECK_RV(rv, "generate key pair", CKR_OK);
    funcList->C_DestroyObject(session, pub);
    funcList->C_DestroyObject(session, priv);
#endif

    /* Use up the token object ids. */
    CHECK_TRUE(WP11_Test_SetNextObjId(slot, 1, (int)OBJ_ID_MAX) == 0,
               "set next token object id to the last id");
    rv = create_data(session, CK_TRUE, "token-last", &tokLast);
    CHECK_RV(rv, "create token object with the last id", CKR_OK);
    CHECK_TRUE(tokLast == (HANDLE_ON_TOKEN | OBJ_ID_MAX),
               "token object handle has the last id");
    rv = create_data(session, CK_TRUE, "token-over", &over);
    CHECK_RV(rv, "token object past the limit fails", CKR_FUNCTION_FAILED);

    rv = create_data(session, CK_FALSE, "session-first", &sessFirst);
    CHECK_RV(rv, "session object with token ids used up", CKR_OK);
    CHECK_TRUE((sessFirst & HANDLE_ON_TOKEN) == 0,
               "session object handle has no token flag");

    /* Use up the session object ids. */
    CHECK_TRUE(WP11_Test_SetNextObjId(slot, 0, (int)OBJ_ID_MAX - 1) == 0,
               "set next session object id below the limit");
    rv = create_data(session, CK_FALSE, "session-last", &sessLast);
    CHECK_RV(rv, "create session object", CKR_OK);
    CHECK_TRUE(sessLast == OBJ_ID_MAX - 1,
               "session object handle has the id and no token flag");
#ifdef HAVE_ECC
    /* The public key takes the last id and the private key fails, so the
     * public key has to be taken back off the session list. */
    rv = gen_keypair(session, &pub, &priv);
    CHECK_RV(rv, "key pair needing two ids fails", CKR_FUNCTION_FAILED);
    CHECK_TRUE(count_objects(session, CK_FALSE) == 2,
               "public key rolled back");
#else
    /* Skip the last id, which the key pair would take. */
    CHECK_TRUE(WP11_Test_SetNextObjId(slot, 0, (int)OBJ_ID_MAX + 1) == 0,
               "use the last session object id");
#endif
    rv = create_data(session, CK_FALSE, "session-over", &over);
    CHECK_RV(rv, "session object past the limit fails", CKR_FUNCTION_FAILED);

    check_label(session, tokFirst, "token-first", "first token object label");
    check_label(session, tokLast, "token-last", "last token object label");
    check_label(session, sessFirst, "session-first",
                "first session object label");
    check_label(session, sessLast, "session-last",
                "last session object label");
    CHECK_TRUE(count_objects(session, CK_TRUE) == 2, "two token objects");
    CHECK_TRUE(count_objects(session, CK_FALSE) == 2, "two session objects");

    rv = funcList->C_DestroyObject(session, sessLast);
    CHECK_RV(rv, "destroy session object", CKR_OK);
    CHECK_TRUE(count_objects(session, CK_TRUE) == 2,
               "token objects kept after session object destroyed");

    /* Closing the session frees its objects. */
    funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);

#ifndef WOLFPKCS11_NO_STORE
    reload_test(tokFirst, tokLast);
#else
    (void)tokLast;
#endif
    pkcs11_unload();
}

#endif /* DEBUG_WOLFPKCS11 */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef DEBUG_WOLFPKCS11
    printf("Debug hook not available, skipping object handle limit test\n");
    return 77;  /* automake: test skipped */
#else
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 object handle limit test ===\n");
    run_test();
    return pkcs11_test_summary();
#endif
}
