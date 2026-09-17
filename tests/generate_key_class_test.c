/* generate_key_class_test.c
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
 * C_GenerateKey must reject a template whose CKA_CLASS or CKA_KEY_TYPE is
 * inconsistent with the generation mechanism.
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

#define TEST_DIR "./store/generate_key_class_test"

#ifndef NO_AES
static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_ULONG valueLen = 16;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE badClass[] = {
        { CKA_VALUE_LEN, &valueLen,   sizeof(valueLen)   },
        { CKA_PRIVATE,   &ckFalse,    sizeof(ckFalse)    },
        { CKA_CLASS,     &dataClass,  sizeof(dataClass)  },
    };
    CK_ATTRIBUTE badKeyType[] = {
        { CKA_VALUE_LEN, &valueLen,   sizeof(valueLen)   },
        { CKA_PRIVATE,   &ckFalse,    sizeof(ckFalse)    },
        { CKA_KEY_TYPE,  &rsaType,    sizeof(rsaType)    },
    };
    CK_ATTRIBUTE goodTmpl[] = {
        { CKA_VALUE_LEN, &valueLen,    sizeof(valueLen)    },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &aesType,     sizeof(aesType)     },
    };
    CK_ATTRIBUTE minimalTmpl[] = {
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_PRIVATE,   &ckFalse,  sizeof(ckFalse)  },
    };
    CK_ATTRIBUTE dupClass[] = {
        { CKA_VALUE_LEN, &valueLen,    sizeof(valueLen)    },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_CLASS,     &dataClass,   sizeof(dataClass)   },
    };

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_GenerateKey(session, &mech, badClass,
                                 sizeof(badClass) / sizeof(*badClass), &key);
    CHECK_RV(rv, "C_GenerateKey(inconsistent CKA_CLASS)",
             CKR_TEMPLATE_INCONSISTENT);

    rv = funcList->C_GenerateKey(session, &mech, badKeyType,
                                 sizeof(badKeyType) / sizeof(*badKeyType),
                                 &key);
    CHECK_RV(rv, "C_GenerateKey(inconsistent CKA_KEY_TYPE)",
             CKR_TEMPLATE_INCONSISTENT);

    rv = funcList->C_GenerateKey(session, &mech, goodTmpl,
                                 sizeof(goodTmpl) / sizeof(*goodTmpl), &key);
    CHECK_RV(rv, "C_GenerateKey(consistent class and type)", CKR_OK);

    rv = funcList->C_GenerateKey(session, &mech, minimalTmpl,
                                 sizeof(minimalTmpl) / sizeof(*minimalTmpl),
                                 &key);
    CHECK_RV(rv, "C_GenerateKey(no class in template)", CKR_OK);

    rv = funcList->C_GenerateKey(session, &mech, dupClass,
                                 sizeof(dupClass) / sizeof(*dupClass), &key);
    CHECK_RV(rv, "C_GenerateKey(duplicate inconsistent CKA_CLASS)",
             CKR_TEMPLATE_INCONSISTENT);

out:
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
    pkcs11_unload();
    return 0;
}
#endif /* !NO_AES */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 C_GenerateKey class consistency test ===\n");
#ifndef NO_AES
    run_test();
#else
    printf("AES not compiled in!\n");
#endif
    return pkcs11_test_summary();
}
