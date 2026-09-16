/* unique_id_test.c
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
 * Every object must carry a token-assigned CKA_UNIQUE_ID that is distinct
 * per object, stable for the life of the object, and rejected when supplied
 * by the caller.
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

#define TEST_DIR "./store/unique_id_test"
#define UNIQUE_ID_MAX 64

static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
#ifndef WOLFPKCS11_NO_STORE
static CK_BBOOL ckTrue = CK_TRUE;
#endif
static CK_BBOOL ckFalse = CK_FALSE;
static byte keyData[16] = { 0 };

static CK_RV get_unique_id(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                           byte* id, CK_ULONG* idLen)
{
    CK_RV rv;
    CK_ATTRIBUTE attr = { CKA_UNIQUE_ID, NULL, 0 };

    rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    if (rv != CKR_OK)
        return rv;
    if (attr.ulValueLen == 0 || attr.ulValueLen == CK_UNAVAILABLE_INFORMATION ||
            attr.ulValueLen > UNIQUE_ID_MAX)
        return CKR_ATTRIBUTE_VALUE_INVALID;

    attr.pValue = id;
    rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    if (rv == CKR_OK)
        *idLen = attr.ulValueLen;
    return rv;
}

static int ids_differ(const byte* a, CK_ULONG aLen, const byte* b,
                      CK_ULONG bLen)
{
    return (aLen != bLen) || (XMEMCMP(a, b, aLen) != 0);
}

static void session_object_tests(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj1 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj2 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE gen = CK_INVALID_HANDLE;
    byte id1[UNIQUE_ID_MAX];
    byte id2[UNIQUE_ID_MAX];
    byte idCopy[UNIQUE_ID_MAX];
    byte idGen[UNIQUE_ID_MAX];
    byte idAgain[UNIQUE_ID_MAX];
    CK_ULONG id1Len = 0;
    CK_ULONG id2Len = 0;
    CK_ULONG idCopyLen = 0;
    CK_ULONG idGenLen = 0;
    CK_ULONG idAgainLen = 0;
    byte callerId[] = "caller-chosen";
    char newLabel[] = "should-not-apply";
    byte gotLabel[64];
    CK_OBJECT_HANDLE foundObjs[8];
    CK_ULONG foundCnt = 0;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_VALUE,    keyData,      sizeof(keyData)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ULONG keyTmplCnt = sizeof(keyTmpl) / sizeof(*keyTmpl);
    CK_ATTRIBUTE keyWithIdTmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass)  },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType)  },
        { CKA_VALUE,     keyData,      sizeof(keyData)      },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)      },
        { CKA_UNIQUE_ID, callerId,     sizeof(callerId) - 1 },
    };
    CK_ULONG keyWithIdTmplCnt = sizeof(keyWithIdTmpl) / sizeof(*keyWithIdTmpl);
    CK_ATTRIBUTE setIdTmpl[] = {
        { CKA_UNIQUE_ID, callerId, sizeof(callerId) - 1 },
    };
    CK_ATTRIBUTE mixedTmpl[] = {
        { CKA_LABEL,     newLabel, sizeof(newLabel) - 1 },
        { CKA_UNIQUE_ID, callerId, sizeof(callerId) - 1 },
    };
    CK_ATTRIBUTE getLabel[] = { { CKA_LABEL, NULL, 0 } };
    CK_ATTRIBUTE findByValue[] = { { CKA_UNIQUE_ID, NULL, 0 } };
    CK_ATTRIBUTE findByNull[] = { { CKA_UNIQUE_ID, NULL, 0 } };
#ifndef NO_AES
    CK_MECHANISM aesGen = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_ULONG aesLen = 16;
    CK_ATTRIBUTE genTmpl[] = {
        { CKA_VALUE_LEN, &aesLen,  sizeof(aesLen)  },
        { CKA_PRIVATE,   &ckFalse, sizeof(ckFalse) },
    };
    CK_ULONG genTmplCnt = sizeof(genTmpl) / sizeof(*genTmpl);
#endif

    rv = funcList->C_CreateObject(session, keyTmpl, keyTmplCnt, &obj1);
    CHECK_RV(rv, "C_CreateObject(first)", CKR_OK);
    rv = funcList->C_CreateObject(session, keyTmpl, keyTmplCnt, &obj2);
    CHECK_RV(rv, "C_CreateObject(second)", CKR_OK);
    if (obj1 == CK_INVALID_HANDLE || obj2 == CK_INVALID_HANDLE)
        goto out;

    rv = get_unique_id(session, obj1, id1, &id1Len);
    CHECK_RV(rv, "C_GetAttributeValue(CKA_UNIQUE_ID first)", CKR_OK);
    rv = get_unique_id(session, obj2, id2, &id2Len);
    CHECK_RV(rv, "C_GetAttributeValue(CKA_UNIQUE_ID second)", CKR_OK);
    CHECK_TRUE(ids_differ(id1, id1Len, id2, id2Len),
               "distinct objects have distinct CKA_UNIQUE_ID");

    rv = get_unique_id(session, obj1, idAgain, &idAgainLen);
    CHECK_RV(rv, "C_GetAttributeValue(CKA_UNIQUE_ID again)", CKR_OK);
    CHECK_TRUE(!ids_differ(id1, id1Len, idAgain, idAgainLen),
               "CKA_UNIQUE_ID is stable across reads");

    rv = funcList->C_CopyObject(session, obj1, NULL, 0, &copy);
    CHECK_RV(rv, "C_CopyObject", CKR_OK);
    if (rv == CKR_OK) {
        rv = get_unique_id(session, copy, idCopy, &idCopyLen);
        CHECK_RV(rv, "C_GetAttributeValue(CKA_UNIQUE_ID copy)", CKR_OK);
        CHECK_TRUE(ids_differ(id1, id1Len, idCopy, idCopyLen),
                   "copy receives its own CKA_UNIQUE_ID");
    }

#ifndef NO_AES
    rv = funcList->C_GenerateKey(session, &aesGen, genTmpl, genTmplCnt, &gen);
    CHECK_RV(rv, "C_GenerateKey(AES)", CKR_OK);
    if (rv == CKR_OK) {
        rv = get_unique_id(session, gen, idGen, &idGenLen);
        CHECK_RV(rv, "C_GetAttributeValue(CKA_UNIQUE_ID generated)", CKR_OK);
        CHECK_TRUE(ids_differ(id1, id1Len, idGen, idGenLen) &&
                   ids_differ(id2, id2Len, idGen, idGenLen),
                   "generated key receives a distinct CKA_UNIQUE_ID");
    }
#endif

    /* A search by the exact CKA_UNIQUE_ID value finds only that object. */
    findByValue[0].pValue = id1;
    findByValue[0].ulValueLen = id1Len;
    rv = funcList->C_FindObjectsInit(session, findByValue, 1);
    CHECK_RV(rv, "C_FindObjectsInit(CKA_UNIQUE_ID value)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, foundObjs, 8, &foundCnt);
        CHECK_RV(rv, "C_FindObjects(CKA_UNIQUE_ID value)", CKR_OK);
        funcList->C_FindObjectsFinal(session);
        CHECK_TRUE(foundCnt == 1 && foundObjs[0] == obj1,
                   "find by CKA_UNIQUE_ID returns the matching object");
    }

    /* A search with a NULL value and a matching length must not crash. */
    findByNull[0].pValue = NULL;
    findByNull[0].ulValueLen = id1Len;
    foundCnt = 0;
    rv = funcList->C_FindObjectsInit(session, findByNull, 1);
    CHECK_RV(rv, "C_FindObjectsInit(CKA_UNIQUE_ID NULL value)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, foundObjs, 8, &foundCnt);
        CHECK_RV(rv, "C_FindObjects(CKA_UNIQUE_ID NULL value)", CKR_OK);
        funcList->C_FindObjectsFinal(session);
        CHECK_TRUE(foundCnt == 0,
                   "find by NULL CKA_UNIQUE_ID matches nothing");
    }

    rv = funcList->C_CreateObject(session, keyWithIdTmpl, keyWithIdTmplCnt,
                                  &obj2);
    CHECK_RV(rv, "C_CreateObject(caller CKA_UNIQUE_ID)",
             CKR_ATTRIBUTE_READ_ONLY);

    rv = funcList->C_CopyObject(session, obj1, setIdTmpl, 1, &copy);
    CHECK_RV(rv, "C_CopyObject(caller CKA_UNIQUE_ID)",
             CKR_ATTRIBUTE_READ_ONLY);

    rv = funcList->C_SetAttributeValue(session, obj1, setIdTmpl, 1);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_UNIQUE_ID)",
             CKR_ATTRIBUTE_READ_ONLY);

    rv = get_unique_id(session, obj1, idAgain, &idAgainLen);
    CHECK_RV(rv, "C_GetAttributeValue(CKA_UNIQUE_ID after set)", CKR_OK);
    CHECK_TRUE(!ids_differ(id1, id1Len, idAgain, idAgainLen),
               "rejected set leaves CKA_UNIQUE_ID unchanged");

    /* A template that also touches CKA_UNIQUE_ID must fail without mutating
     * the mutable attribute that precedes it. */
    getLabel[0].pValue = gotLabel;
    getLabel[0].ulValueLen = sizeof(gotLabel);
    rv = funcList->C_SetAttributeValue(session, obj1, mixedTmpl, 2);
    CHECK_RV(rv, "C_SetAttributeValue(CKA_LABEL + CKA_UNIQUE_ID)",
             CKR_ATTRIBUTE_READ_ONLY);

    rv = funcList->C_GetAttributeValue(session, obj1, getLabel, 1);
    CHECK_RV(rv, "C_GetAttributeValue(CKA_LABEL after mixed set)", CKR_OK);
    CHECK_TRUE(getLabel[0].ulValueLen == 0,
               "rejected mixed set leaves CKA_LABEL unchanged");

out:
    return;
}

#ifndef WOLFPKCS11_NO_STORE
static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "unique-id-token";

static CK_RV token_init(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE soSession = 0;
    unsigned char label[32];

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
    *slot = slotList[0];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    rv = funcList->C_InitToken(*slot, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin), label);
    if (rv != CKR_OK)
        return rv;

    rv = funcList->C_OpenSession(*slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
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

static CK_RV user_session(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    CK_RV rv;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, session);
    if (rv != CKR_OK)
        return rv;
    return funcList->C_Login(*session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                             (CK_ULONG)XSTRLEN(userPin));
}

static void token_object_tests(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_C_INITIALIZE_ARGS args;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
    CK_ULONG foundCnt = 0;
    byte idBefore[UNIQUE_ID_MAX];
    byte idAfter[UNIQUE_ID_MAX];
    CK_ULONG idBeforeLen = 0;
    CK_ULONG idAfterLen = 0;
    char objLabel[] = "unique-id-token-object";
    CK_ATTRIBUTE tokenTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass)   },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType)   },
        { CKA_VALUE,    keyData,      sizeof(keyData)       },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)        },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)       },
        { CKA_LABEL,    objLabel,     sizeof(objLabel) - 1  },
    };
    CK_ULONG tokenTmplCnt = sizeof(tokenTmpl) / sizeof(*tokenTmpl);
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_LABEL, objLabel, sizeof(objLabel) - 1 },
    };

    rv = token_init(&slot);
    CHECK_RV(rv, "token init", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = user_session(slot, &session);
    CHECK_RV(rv, "user session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CreateObject(session, tokenTmpl, tokenTmplCnt, &obj);
    CHECK_RV(rv, "C_CreateObject(token object)", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = get_unique_id(session, obj, idBefore, &idBeforeLen);
    CHECK_RV(rv, "C_GetAttributeValue(CKA_UNIQUE_ID token object)", CKR_OK);

    funcList->C_Logout(session);
    funcList->C_CloseSession(session);
    session = 0;
    funcList->C_Finalize(NULL);

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "C_Initialize(reload)", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = user_session(slot, &session);
    CHECK_RV(rv, "user session (reload)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_FindObjectsInit(session, findTmpl, 1);
    CHECK_RV(rv, "C_FindObjectsInit(label)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, &found, 1, &foundCnt);
        CHECK_RV(rv, "C_FindObjects(label)", CKR_OK);
        funcList->C_FindObjectsFinal(session);
    }
    CHECK_TRUE(foundCnt == 1, "token object found after reload");
    if (foundCnt == 1) {
        rv = get_unique_id(session, found, idAfter, &idAfterLen);
        CHECK_RV(rv, "C_GetAttributeValue(CKA_UNIQUE_ID after reload)",
                 CKR_OK);
        CHECK_TRUE(!ids_differ(idBefore, idBeforeLen, idAfter, idAfterLen),
                   "token object keeps its CKA_UNIQUE_ID across reload");
        funcList->C_DestroyObject(session, found);
    }

out:
    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    funcList->C_Finalize(NULL);
}
#endif /* !WOLFPKCS11_NO_STORE */

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
        session_object_tests(session);
        funcList->C_CloseSession(session);
    }
    funcList->C_Finalize(NULL);

#ifndef WOLFPKCS11_NO_STORE
    token_object_tests();
#endif

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

    printf("=== wolfPKCS11 CKA_UNIQUE_ID test ===\n");
    run_test();
    return pkcs11_test_summary();
}
