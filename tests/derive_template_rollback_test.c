/* derive_template_rollback_test.c
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
 * Tests C_DeriveKey templates weaker than the base key.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"

#define TEST_DIR "./store/derive_template_rollback_test"

static int test_passed = 0;
static int test_failed = 0;

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static const char* tokenName = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static void check(int cond, const char* msg)
{
    if (cond) {
        printf("PASS: %s\n", msg);
        test_passed++;
    }
    else {
        fprintf(stderr, "FAIL: %s\n", msg);
        test_failed++;
    }
}

static void check_rv(CK_RV rv, CK_RV exp, const char* msg)
{
    if (rv != exp)
        fprintf(stderr, "  got 0x%lx, expected 0x%lx\n", (unsigned long)rv,
                (unsigned long)exp);
    check(rv == exp, msg);
}

#if (defined(HAVE_ECC) && !defined(WOLFPKCS11_LEGACY_DERIVE_NO_INHERIT) && \
     !defined(WOLFPKCS11_NSS)) || !defined(NO_DH) || defined(WOLFSSL_HAVE_PRF)
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static void destroy_obj(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* obj)
{
    if (*obj != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, *obj);
        *obj = CK_INVALID_HANDLE;
    }
}
#endif

#if defined(HAVE_ECC) && !defined(WOLFPKCS11_LEGACY_DERIVE_NO_INHERIT) && \
    !defined(WOLFPKCS11_NSS)
static CK_RV read_bool(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                       CK_ATTRIBUTE_TYPE type, CK_BBOOL* out)
{
    CK_ATTRIBUTE attr = { type, out, sizeof(*out) };

    return funcList->C_GetAttributeValue(session, obj, &attr, 1);
}

static CK_RV ecdh_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                         CK_BBOOL* sensitive, CK_BBOOL* extractable,
                         CK_OBJECT_HANDLE* key)
{
    CK_ULONG len = 32;
    CK_ECDH1_DERIVE_PARAMS params;
    CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    CK_ATTRIBUTE tmpl[4] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
    };
    CK_ULONG cnt = 3;

    XMEMSET(&params, 0, sizeof(params));
    params.kdf = CKD_NULL;
    params.pPublicData = ecc_p256_point;
    params.ulPublicDataLen = sizeof(ecc_p256_point);
    if (sensitive != NULL) {
        tmpl[cnt].type = CKA_SENSITIVE;
        tmpl[cnt].pValue = sensitive;
        tmpl[cnt++].ulValueLen = sizeof(CK_BBOOL);
    }
    else if (extractable != NULL) {
        tmpl[cnt].type = CKA_EXTRACTABLE;
        tmpl[cnt].pValue = extractable;
        tmpl[cnt++].ulValueLen = sizeof(CK_BBOOL);
    }
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl, cnt, key);
}

static void test_ecdh_weaker_template(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE plain = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_BBOOL val = 0xAA;
    CK_BBOOL baseVal = 0x55;
    CK_BBOOL sensitive = CK_TRUE;
    CK_BBOOL extractable = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &privClass,      sizeof(privClass)       },
        { CKA_KEY_TYPE,    &ecType,         sizeof(ecType)          },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS,   ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,       ecc_p256_priv,   sizeof(ecc_p256_priv)   },
        { CKA_SENSITIVE,   &sensitive,      sizeof(sensitive)       },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)     },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    printf("\n--- ECDH derive templates against base protection ---\n");
    rv = funcList->C_CreateObject(session, tmpl, cnt, &base);
    check_rv(rv, CKR_OK, "create protected EC private key");
    if (rv == CKR_OK) {
        sensitive = CK_FALSE;
        extractable = CK_TRUE;
        rv = funcList->C_CreateObject(session, tmpl, cnt, &plain);
        check_rv(rv, CKR_OK, "create plain EC private key");
    }
    if (rv != CKR_OK)
        goto cleanup;

    rv = ecdh_derive(session, base, &ckFalse, NULL, &key);
    check_rv(rv, CKR_TEMPLATE_INCONSISTENT,
             "CKA_SENSITIVE=FALSE under a sensitive base refused");
    check(key == CK_INVALID_HANDLE, "no key from the refused template");
    destroy_obj(session, &key);

    rv = ecdh_derive(session, base, NULL, &ckTrue, &key);
    check_rv(rv, CKR_TEMPLATE_INCONSISTENT,
             "CKA_EXTRACTABLE=TRUE under a non-extractable base refused");
    check(key == CK_INVALID_HANDLE, "no key from the refused template");
    destroy_obj(session, &key);

    rv = ecdh_derive(session, base, NULL, NULL, &key);
    check_rv(rv, CKR_OK, "derive with protection left out");
    if (rv == CKR_OK) {
        rv = read_bool(session, key, CKA_SENSITIVE, &val);
        check(rv == CKR_OK && val == CK_TRUE,
              "omitted CKA_SENSITIVE inherited");
        rv = read_bool(session, key, CKA_EXTRACTABLE, &val);
        check(rv == CKR_OK && val == CK_FALSE,
              "omitted CKA_EXTRACTABLE inherited");
        rv = read_bool(session, base, CKA_ALWAYS_SENSITIVE, &baseVal);
        if (rv == CKR_OK)
            rv = read_bool(session, key, CKA_ALWAYS_SENSITIVE, &val);
        check(rv == CKR_OK && val == baseVal,
              "CKA_ALWAYS_SENSITIVE follows the protected base");
    }
    destroy_obj(session, &key);

    rv = ecdh_derive(session, base, &ckTrue, NULL, &key);
    check_rv(rv, CKR_OK, "CKA_SENSITIVE=TRUE under a sensitive base allowed");
    destroy_obj(session, &key);

    rv = ecdh_derive(session, plain, &ckTrue, NULL, &key);
    check_rv(rv, CKR_OK, "CKA_SENSITIVE=TRUE under a plain base allowed");
    if (rv == CKR_OK) {
        rv = read_bool(session, key, CKA_ALWAYS_SENSITIVE, &val);
        check(rv == CKR_OK && val == CK_FALSE,
              "CKA_ALWAYS_SENSITIVE follows the plain base");
    }
    destroy_obj(session, &key);

    rv = ecdh_derive(session, plain, &ckFalse, NULL, &key);
    check_rv(rv, CKR_OK, "CKA_SENSITIVE=FALSE under a plain base allowed");
    destroy_obj(session, &key);

cleanup:
    destroy_obj(session, &plain);
    destroy_obj(session, &base);
}
#endif

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);

#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return -1;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        dlclose(dlib);
        return -1;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK)
        return ret;
#endif

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (ret != CKR_OK)
        return ret;
    if (slotCount == 0)
        return CKR_GENERAL_ERROR;
    slot = slotList[0];
    return ret;
}

static void pkcs11_final(void)
{
    if (funcList != NULL) {
        funcList->C_Finalize(NULL);
        funcList = NULL;
    }
#ifndef HAVE_PKCS11_STATIC
    if (dlib) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
}

static CK_RV pkcs11_setup_token(void)
{
    CK_RV ret;
    unsigned char label[32];
    CK_SESSION_HANDLE soSession;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));
    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &soSession);
    if (ret != CKR_OK)
        return ret;
    ret = funcList->C_Login(soSession, CKU_SO, soPin, soPinLen);
    if (ret == CKR_OK)
        ret = funcList->C_InitPIN(soSession, userPin, userPinLen);
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    return ret;
}

int main(int argc, char* argv[])
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif
    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 Derive Template and Rollback Test ===\n");

    rv = pkcs11_init();
    check_rv(rv, CKR_OK, "C_Initialize");
    if (rv == CKR_OK) {
        rv = pkcs11_setup_token();
        check_rv(rv, CKR_OK, "token setup");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
        check_rv(rv, CKR_OK, "C_OpenSession");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        check_rv(rv, CKR_OK, "C_Login");
    }
    if (rv == CKR_OK) {
#if defined(HAVE_ECC) && !defined(WOLFPKCS11_LEGACY_DERIVE_NO_INHERIT) && \
    !defined(WOLFPKCS11_NSS)
        test_ecdh_weaker_template(session);
#endif
    }
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    return (test_failed == 0) ? 0 : 1;
}
