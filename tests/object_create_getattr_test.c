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
