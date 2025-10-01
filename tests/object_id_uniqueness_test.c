/* object_id_uniqueness_test.c
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
 * Test for object ID uniqueness bug - nextObjId should not reset on
 * C_Initialize when objects are loaded from storage
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#include "storage_helpers.h"

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#if !defined(WOLFPKCS11_NO_STORE)

#include "testdata.h"

/* Minimal unit test macros */
#define CHECK_COND(cond, ret, msg)                                         \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "\n%s:%d - %s - FAIL\n",                       \
                    __FILE__, __LINE__, msg);                              \
            ret = -1;                                                      \
        }                                                                  \
    }                                                                      \
    while (0)
#define CHECK_CKR(rv, msg)                                                 \
    do {                                                                   \
        if (rv != CKR_OK) {                                                \
            fprintf(stderr, "\n%s:%d - %s: %lx - FAIL\n",                  \
                    __FILE__, __LINE__, msg, rv);                          \
        }                                                                  \
    }                                                                      \
    while (0)
#define CHECK_CKR_FAIL(rv, exp, msg)                                       \
    do {                                                                   \
        if (rv != exp) {                                                   \
            fprintf(stderr, "\n%s:%d - %s RETURNED %lx - FAIL\n",          \
                    __FILE__, __LINE__, msg, rv);                          \
            if (rv == CKR_OK)                                              \
                rv = -1;                                                   \
        }                                                                  \
        else                                                               \
            rv = CKR_OK;                                                   \
    }                                                                      \
    while (0)

#if (!defined(WOLFPKCS11_NO_STORE) && !defined(NO_RSA) && !defined(NO_HMAC))
static int verbose = 0;

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static unsigned char tokenName[32] = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
static CK_CERTIFICATE_TYPE certType = CKC_X_509;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

/* Simple X.509 certificate for testing */
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

static const unsigned char testCert2[] = {
    0x30, 0x82, 0x01, 0x0A, 0x30, 0x81, 0xB7, 0xA0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x01, 0x02, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x04, 0x03, 0x02, 0x30, 0x12, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0C, 0x07, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30,
    0x1E, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x15, 0x31, 0x13, 0x30,
    0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0A, 0x54, 0x65, 0x73, 0x74,
    0x20, 0x43, 0x65, 0x72, 0x74, 0x20, 0x32, 0x30, 0x59, 0x30, 0x13, 0x06,
    0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x41, 0x42,
    0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
    0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
    0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
    0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
    0x7F, 0x80, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,
    0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
    0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x02, 0x21, 0x00, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C,
    0x7D, 0x7E, 0x7F
};

static const char testLabel1[] = "TestCert1";
static const char testLabel2[] = "TestCert2";
static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_INFO info;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;
#endif

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;

#ifndef HAVE_PKCS11_STATIC
    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return -1;
    }

    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        return -1;
    }

    ret = func(&funcList);
#else
    ret = C_GetFunctionList(&funcList);
#endif
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list\n");
        return ret;
    }

    ret = funcList->C_Initialize(&args);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to initialize PKCS#11\n");
        return ret;
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetInfo(&info);
        CHECK_CKR(ret, "Get Info");
    }

    /* Get available slots */
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
        CHECK_CKR(ret, "Get Slot List");
    }

    if (ret == CKR_OK && slotCount > 0) {
        slot = slotList[0];  /* Use first available slot */
    } else if (ret == CKR_OK) {
        fprintf(stderr, "No slots available\n");
        ret = CKR_GENERAL_ERROR;
    }

    return ret;
}

static CK_RV pkcs11_final(void)
{
    CK_RV ret;

    ret = funcList->C_Finalize(NULL);
    CHECK_CKR(ret, "Finalize");

#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif

    return ret;
}

static CK_RV pkcs11_init_token(void)
{
    CK_RV ret;

    ret = funcList->C_InitToken(slot, soPin, soPinLen, tokenName);
    CHECK_CKR(ret, "Init Token");

    return ret;
}

static CK_RV pkcs11_set_user_pin(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session;

    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  NULL, NULL, &session);
    CHECK_CKR(ret, "Open Session");

    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Login SO");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_InitPIN(session, userPin, userPinLen);
        CHECK_CKR(ret, "Init PIN");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_Logout(session);
        CHECK_CKR(ret, "Logout");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_CloseSession(session);
        CHECK_CKR(ret, "Close Session");
    }

    return ret;
}

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;

    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  NULL, NULL, session);
    CHECK_CKR(ret, "Open Session");

    if (ret == CKR_OK) {
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login User");
    }

    return ret;
}

static CK_RV pkcs11_close_session(CK_SESSION_HANDLE session)
{
    CK_RV ret;

    ret = funcList->C_Logout(session);
    CHECK_CKR(ret, "Logout");

    if (ret == CKR_OK) {
        ret = funcList->C_CloseSession(session);
        CHECK_CKR(ret, "Close Session");
    }

    return ret;
}

static CK_RV create_token_cert_object(CK_SESSION_HANDLE session,
                                      const unsigned char* certData,
                                      CK_ULONG certLen, const char* label,
                                      CK_OBJECT_HANDLE* objHandle)
{
    CK_RV ret;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS,             &certClass,      sizeof(certClass) },
        { CKA_CERTIFICATE_TYPE,  &certType,       sizeof(certType) },
        { CKA_TOKEN,             &ckTrue,         sizeof(ckTrue) },
        { CKA_PRIVATE,           &ckFalse,        sizeof(ckFalse) },
        { CKA_MODIFIABLE,        &ckTrue,         sizeof(ckTrue) },
        { CKA_LABEL,             (char*)label,    strlen(label) },
        { CKA_VALUE,             (char*)certData, certLen }
    };
    CK_ULONG templateCount = sizeof(template) / sizeof(template[0]);

    ret = funcList->C_CreateObject(session, template, templateCount, objHandle);
    CHECK_CKR(ret, "Create Token Certificate Object");

    return ret;
}

static CK_RV find_all_objects(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE* objects,
                              CK_ULONG* objectCount)
{
    CK_RV ret;
    CK_ATTRIBUTE findTemplate[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) }
    };
    CK_ULONG findTemplateCount = sizeof(findTemplate) / sizeof(findTemplate[0]);

    ret = funcList->C_FindObjectsInit(session, findTemplate, findTemplateCount);
    CHECK_CKR(ret, "Find Objects Init");

    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, objects, 10, objectCount);
        CHECK_CKR(ret, "Find Objects");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "Find Objects Final");
    }

    return ret;
}

static CK_RV object_id_uniqueness_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session1, session2 = 0;
    CK_OBJECT_HANDLE obj1, obj2;
    CK_OBJECT_HANDLE foundObjects[10];
    CK_ULONG foundCount;

    printf("Object ID Uniqueness Test\n");
    printf("=========================\n");

    /* Step 1: Initialize PKCS#11 */
    ret = pkcs11_init();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to initialize PKCS#11\n");
        return ret;
    }

    /* Step 1a: Initialize token */
    ret = pkcs11_init_token();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to initialize token\n");
        goto cleanup;
    }

    /* Step 1b: Set user PIN */
    ret = pkcs11_set_user_pin();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to set user PIN\n");
        goto cleanup;
    }

    /* Step 2: Open session and create first token data object */
    ret = pkcs11_open_session(&session1);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to open first session\n");
        goto cleanup;
    }

    printf("Creating first token certificate object...\n");
    ret = create_token_cert_object(session1, testCert1, sizeof(testCert1),
                                   testLabel1, &obj1);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to create first token certificate object\n");
        goto cleanup;
    }

    printf("First object created with handle: 0x%lx\n", obj1);

    /* Step 3: Close session and finalize */
    printf("Closing session and finalizing...\n");
    pkcs11_close_session(session1);
    pkcs11_final();

    /* Step 4: Re-initialize PKCS#11 */
    printf("Re-initializing PKCS#11...\n");
    ret = pkcs11_init();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to re-initialize PKCS#11\n");
        return ret;
    }

    /* Step 5: Open new session and create second token data object */
    ret = pkcs11_open_session(&session2);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to open second session\n");
        goto cleanup;
    }

    printf("Creating second token certificate object...\n");
    ret = create_token_cert_object(session2, testCert2, sizeof(testCert2),
                                   testLabel2, &obj2);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to create second token certificate object\n");
        goto cleanup;
    }

    printf("Second object created with handle: 0x%lx\n", obj2);

    /* Step 6: Find all objects and check for unique IDs */
    printf("Finding all token objects...\n");
    ret = find_all_objects(session2, foundObjects, &foundCount);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to find objects\n");
        goto cleanup;
    }

    printf("Found %lu token objects:\n", foundCount);
    for (CK_ULONG i = 0; i < foundCount; i++) {
        printf("  Object %lu: handle=0x%lx\n", i + 1, foundObjects[i]);
    }

    /* Step 7: Check for object handle uniqueness (which reflects
     * ID uniqueness) */
    printf("Checking object handle uniqueness...\n");
    for (CK_ULONG i = 0; i < foundCount; i++) {
        for (CK_ULONG j = i + 1; j < foundCount; j++) {
            if (foundObjects[i] == foundObjects[j]) {
                fprintf(stderr, "ERROR: Objects have duplicate handles!\n");
                fprintf(stderr,
                        "  Object %lu and Object %lu both have handle=0x%lx\n",
                        i + 1, j + 1, foundObjects[i]);
                ret = CKR_GENERAL_ERROR;
                goto cleanup;
            }
        }
    }

    /* Step 8: Verify we have at least 2 objects */
    if (foundCount < 2) {
        fprintf(stderr, "ERROR: Expected at least 2 objects, but found %lu\n",
                foundCount);
        ret = CKR_GENERAL_ERROR;
        goto cleanup;
    }

    printf("SUCCESS: All object handles are unique!\n");

cleanup:
    if (session2 != 0) {
        pkcs11_close_session(session2);
    }
    pkcs11_final();
    return ret;
}
#endif /* (!defined(WOLFPKCS11_NO_STORE) && !defined(NO_RSA)) */

#endif /* !WOLFPKCS11_NO_STORE */

int main(int argc, char* argv[])
{
#if (!defined(WOLFPKCS11_NO_STORE) && !defined(NO_RSA) && !defined(NO_HMAC))
    CK_RV ret;
    int init_ret;

    init_ret = unit_init_storage();
    if (init_ret != 0) {
        fprintf(stderr, "wolfBoot storage init failed: %d\n", init_ret);
        return 1;
    }

#ifndef WOLFPKCS11_NO_ENV
    if (!XGETENV("WOLFPKCS11_TOKEN_PATH")) {
        XSETENV("WOLFPKCS11_TOKEN_PATH", "./store/object", 1);
    }
#endif

    if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        verbose = 1;
    }

    printf("wolfPKCS11 Object ID Uniqueness Test\n");
    printf("====================================\n\n");

    ret = object_id_uniqueness_test();
    if (ret == CKR_OK) {
        printf("\nAll tests passed!\n");
        return 0;
    } else {
        printf("\nTest failed with error: %lx\n", ret);
        return 1;
    }
#else
    (void)argc;
    (void)argv;
    printf("KeyStore not compiled in!\n");
    return 77;
#endif
}
