/* nss_email_store_test.c
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
 * A token object that carries an NSS email attribute must persist and reload
 * that attribute intact. The stored object metadata reserves room for the
 * email field, so the final write of a token object with an email must not
 * overflow the reserved size.
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

#define TEST_DIR "./store/nss_email_store_test"

#if defined(WOLFPKCS11_NSS) && !defined(WOLFPKCS11_NO_STORE)

static const unsigned char testCert1[] = {
    0x30, 0x82, 0x01, 0x0A, 0x30, 0x81, 0xB7, 0xA0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x04, 0x03, 0x02, 0x30, 0x12, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0C, 0x07, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30,
    0x1E, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x15, 0x31, 0x13, 0x30,
    0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0A, 0x54, 0x65, 0x73, 0x74,
    0x20, 0x43, 0x65, 0x72, 0x74, 0x20, 0x31, 0x30, 0x59, 0x30, 0x13, 0x06,
    0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
    0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
    0x3F, 0x40, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,
    0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
    0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x02, 0x21, 0x00, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
    0x3D, 0x3E, 0x3F
};

static CK_SLOT_ID slot = 0;
static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "nss-email-token";

static const byte emailValue[] = "user@example.com";
static const byte idValue[]    = { 0x01, 0x02, 0x03, 0x04 };
static const char objLabel[]   = "nss-email-object";

static CK_RV init_library(void)
{
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
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
    return CKR_OK;
}

static CK_RV init_token(void)
{
    unsigned char label[32];
    CK_SESSION_HANDLE soSession = 0;
    CK_RV rv;

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

static CK_RV user_session(CK_SESSION_HANDLE* session)
{
    CK_RV rv;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, session);
    if (rv != CKR_OK)
        return rv;
    return funcList->C_Login(*session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                             (CK_ULONG)XSTRLEN(userPin));
}

static int run_test(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
    CK_ULONG foundCnt = 0;
    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    byte gotEmail[64];
    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,            &certClass,        sizeof(certClass)      },
        { CKA_CERTIFICATE_TYPE, &certType,         sizeof(certType)       },
        { CKA_TOKEN,            &ckTrue,           sizeof(ckTrue)         },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)        },
        { CKA_LABEL,            (void*)objLabel,   sizeof(objLabel) - 1   },
        { CKA_ID,               (void*)idValue,    sizeof(idValue)        },
        { CKA_VALUE,            (void*)testCert1,  sizeof(testCert1)      },
        { CKA_NSS_EMAIL,        (void*)emailValue, sizeof(emailValue) - 1 },
    };
    CK_ULONG createTmplCnt = sizeof(createTmpl) / sizeof(*createTmpl);
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_LABEL, (void*)objLabel, sizeof(objLabel) - 1 },
    };
    CK_ATTRIBUTE getEmail[] = {
        { CKA_NSS_EMAIL, gotEmail, sizeof(gotEmail) },
    };

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = init_library();
    CHECK_RV(rv, "initialize", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = init_token();
    CHECK_RV(rv, "init token", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = user_session(&session);
    CHECK_RV(rv, "user session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    /* Storing this token object writes its email into the object metadata. */
    rv = funcList->C_CreateObject(session, createTmpl, createTmplCnt, &obj);
    CHECK_RV(rv, "C_CreateObject(token object with email)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    funcList->C_Logout(session);
    funcList->C_CloseSession(session);
    session = 0;
    funcList->C_Finalize(NULL);

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "re-initialize", CKR_OK);
    if (rv != CKR_OK)
        return -1;
    rv = user_session(&session);
    CHECK_RV(rv, "user session (reload)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_FindObjectsInit(session, findTmpl, 1);
    CHECK_RV(rv, "C_FindObjectsInit", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, &found, 1, &foundCnt);
        CHECK_RV(rv, "C_FindObjects", CKR_OK);
        funcList->C_FindObjectsFinal(session);
    }
    CHECK_TRUE(foundCnt == 1, "token object with email found after reload");

    if (foundCnt == 1) {
        rv = funcList->C_GetAttributeValue(session, found, getEmail, 1);
        CHECK_RV(rv, "C_GetAttributeValue(CKA_NSS_EMAIL)", CKR_OK);
        CHECK_TRUE(getEmail[0].ulValueLen == sizeof(emailValue) - 1 &&
                   XMEMCMP(gotEmail, emailValue, sizeof(emailValue) - 1) == 0,
                   "email attribute preserved across reload");
        funcList->C_DestroyObject(session, found);
    }

out:
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

    printf("=== wolfPKCS11 NSS email store test ===\n");
    run_test();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("NSS keystore support not compiled in!\n");
    return 77;
}

#endif /* WOLFPKCS11_NSS && !WOLFPKCS11_NO_STORE */
