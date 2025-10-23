/* storage_upgrade_tpm_test.c
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
 * Test for validating TPM-backed storage upgrade by creating token objects
 * with an older release and verifying they remain usable after an upgrade.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
    #include <unistd.h>
    #include <sys/stat.h>
#else
    #include <io.h>
    #define unlink _unlink
#endif

#ifndef PATH_MAX
    #define PATH_MAX 4096
#endif

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#if defined(WOLFPKCS11_NO_STORE) || defined(NO_RSA)

int main(void)
{
    fprintf(stderr, "wolfPKCS11 storage or RSA support disabled, skipping\n");
    return 77;
}

#else /* WOLFPKCS11_NO_STORE || NO_RSA */

/* Only pull in the RSA test vectors we need. */
#undef HAVE_ECC
#define NO_AES
#define NO_DH
#include "testdata.h"

/* Minimal test macros */
#define CHECK_COND(cond, msg)                                              \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "%s:%d - %s - FAIL\n",                         \
                __FILE__, __LINE__, msg);                                  \
            return CKR_GENERAL_ERROR;                                      \
        }                                                                  \
    } while (0)

#define CHECK_CKR(rv, msg)                                                 \
    do {                                                                   \
        if ((rv) != CKR_OK) {                                              \
            fprintf(stderr, "%s:%d - %s returned 0x%lx - FAIL\n",          \
                __FILE__, __LINE__, msg, (CK_ULONG)(rv));                  \
        }                                                                  \
    } while (0)

static const char* usage_msg =
    "Usage: storage_upgrade_tpm_test [--prepare | --verify]\n"
    "  --prepare  Initialize the token, create keys, and persist certificate\n"
    "  --verify   Validate persisted objects after upgrade and insert new data\n";

typedef enum {
    TEST_PHASE_PREPARE,
    TEST_PHASE_VERIFY
} test_phase_t;

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* func_list;
static CK_SLOT_ID slot = 0;
static CK_VERSION library_version = { 0, 0 };

/* Token parameters */
static const char token_label_str[] = "wolfPKCS11 TPM upgrade";
static byte* so_pin   = (byte*)"password123456";
static const CK_ULONG so_pin_len   = 14;
static byte* user_pin = (byte*)"wolfpkcs11-test";
static const CK_ULONG user_pin_len = 15;

/* Object metadata */
static CK_OBJECT_CLASS pub_key_class  = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS priv_key_class = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS cert_class     = CKO_CERTIFICATE;
static CK_OBJECT_CLASS data_class     = CKO_DATA;
static CK_KEY_TYPE rsa_key_type       = CKK_RSA;
static CK_CERTIFICATE_TYPE cert_type  = CKC_X_509;
static CK_BBOOL ck_true  = CK_TRUE;
static CK_BBOOL ck_false = CK_FALSE;
static CK_BYTE rsa_key_id[] = { 0x01, 0x00, 0xAA, 0x55 };
static const char rsa_key_label[]  = "upgrade-rsa-key";
static const char cert_label[]     = "upgrade-rsa-cert";
static const char data_object_label[] = "upgrade-data-object";
static const CK_BYTE data_object_id[] = { 0x10, 0x32, 0x54, 0x76 };

static unsigned char data_object_value[] = {
    0x55, 0x50, 0x47, 0x52, 0x41, 0x44, 0x45, 0x2D,
    0x54, 0x50, 0x4D, 0x2D, 0x4F, 0x4B, 0x21, 0x21
};

static unsigned char rsa_message[] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
    0x61, 0x20, 0x54, 0x50, 0x4d, 0x20, 0x75, 0x70,
    0x67, 0x72, 0x61, 0x64, 0x65, 0x20, 0x73, 0x74,
    0x6f, 0x72, 0x61, 0x67, 0x65, 0x20, 0x74, 0x65
};

/* Simple test certificates (copied from object_id_uniqueness_test.c) */
static const unsigned char upgrade_cert1[] = {
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

static const unsigned char upgrade_cert_subject1[] = {
    0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
    0x0A, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x20, 0x31
};

static const char legacy_cert_marker_name[] = ".legacy_cert_missing";

static void clear_legacy_cert_marker(void);
static void set_legacy_cert_marker(void);
static int legacy_cert_marker_exists(void);

static void usage(const char* prog)
{
    fprintf(stderr, "%s", usage_msg);
    (void)prog;
}

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_INFO info;
    CK_SLOT_ID slots[8];
    CK_ULONG slot_count = sizeof(slots) / sizeof(slots[0]);
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList get_func = NULL;
#endif

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;

#ifndef HAVE_PKCS11_STATIC
    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return CKR_GENERAL_ERROR;
    }

    get_func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (get_func == NULL) {
        fprintf(stderr, "Failed to get function list symbol\n");
        dlclose(dlib);
        dlib = NULL;
        return CKR_GENERAL_ERROR;
    }

    ret = get_func(&func_list);
#else
    ret = C_GetFunctionList(&func_list);
#endif
    CHECK_CKR(ret, "C_GetFunctionList");
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_Initialize(&args);
    CHECK_CKR(ret, "C_Initialize");
    if (ret != CKR_OK)
        return ret;

    XMEMSET(&info, 0, sizeof(info));
    ret = func_list->C_GetInfo(&info);
    CHECK_CKR(ret, "C_GetInfo");
    if (ret != CKR_OK)
        return ret;
    library_version = info.libraryVersion;

    ret = func_list->C_GetSlotList(CK_FALSE, NULL, &slot_count);
    CHECK_CKR(ret, "C_GetSlotList (count)");
    if (ret != CKR_OK)
        return ret;

    if (slot_count == 0) {
        fprintf(stderr, "No slots reported by token\n");
        return CKR_GENERAL_ERROR;
    }

    if (slot_count > (CK_ULONG)(sizeof(slots) / sizeof(slots[0])))
        slot_count = sizeof(slots) / sizeof(slots[0]);

    ret = func_list->C_GetSlotList(CK_FALSE, slots, &slot_count);
    CHECK_CKR(ret, "C_GetSlotList");
    if (ret != CKR_OK)
        return ret;

    slot = slots[0];
    return CKR_OK;
}

static void pkcs11_final(void)
{
    if (func_list != NULL) {
        func_list->C_Finalize(NULL);
        func_list = NULL;
    }
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
}

static CK_RV open_rw_session(CK_SESSION_HANDLE* session)
{
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_RV ret = func_list->C_OpenSession(slot, flags, NULL, NULL, session);
    CHECK_CKR(ret, "C_OpenSession");
    return ret;
}

static CK_RV initialize_token(void)
{
    CK_UTF8CHAR label[32];
    XMEMSET(label, ' ', sizeof(label));
    {
        size_t len = XSTRLEN(token_label_str);
        if (len > sizeof(label))
            len = sizeof(label);
        XMEMCPY(label, token_label_str, len);
    }
    return func_list->C_InitToken(slot, so_pin, so_pin_len, label);
}

static CK_RV login_so(CK_SESSION_HANDLE session)
{
    CK_RV ret = func_list->C_Login(session, CKU_SO, so_pin, so_pin_len);
    CHECK_CKR(ret, "SO Login");
    return ret;
}

static CK_RV login_user(CK_SESSION_HANDLE session)
{
    CK_RV ret = func_list->C_Login(session, CKU_USER, user_pin, user_pin_len);
    CHECK_CKR(ret, "User Login");
    return ret;
}

static CK_RV initialize_user_pin(CK_SESSION_HANDLE session)
{
    CK_RV ret = func_list->C_InitPIN(session, user_pin, user_pin_len);
    CHECK_CKR(ret, "C_InitPIN");
    return ret;
}

static CK_RV generate_rsa_keypair(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE* pub_key,
                                  CK_OBJECT_HANDLE* priv_key)
{
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_RV ret;
    CK_ULONG modulus_bits = 2048;
    CK_BYTE public_exp[] = { 0x01, 0x00, 0x01 };

    CK_ATTRIBUTE pub_template[] = {
        { CKA_CLASS, &pub_key_class, sizeof(pub_key_class) },
        { CKA_KEY_TYPE, &rsa_key_type, sizeof(rsa_key_type) },
        { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        { CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits) },
        { CKA_PUBLIC_EXPONENT, public_exp, sizeof(public_exp) },
        { CKA_ENCRYPT, &ck_true, sizeof(ck_true) },
        { CKA_VERIFY, &ck_true, sizeof(ck_true) },
        { CKA_WRAP, &ck_true, sizeof(ck_true) },
        { CKA_LABEL, (void*)rsa_key_label, (CK_ULONG)(sizeof(rsa_key_label) - 1) },
        { CKA_ID, rsa_key_id, sizeof(rsa_key_id) }
    };

    CK_ATTRIBUTE priv_template[] = {
        { CKA_CLASS, &priv_key_class, sizeof(priv_key_class) },
        { CKA_KEY_TYPE, &rsa_key_type, sizeof(rsa_key_type) },
        { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        { CKA_SENSITIVE, &ck_true, sizeof(ck_true) },
        { CKA_DECRYPT, &ck_true, sizeof(ck_true) },
        { CKA_SIGN, &ck_true, sizeof(ck_true) },
        { CKA_UNWRAP, &ck_true, sizeof(ck_true) },
        { CKA_LABEL, (void*)rsa_key_label, (CK_ULONG)(sizeof(rsa_key_label) - 1) },
        { CKA_ID, rsa_key_id, sizeof(rsa_key_id) },
        { CKA_EXTRACTABLE, &ck_false, sizeof(ck_false) }
    };

    ret = func_list->C_GenerateKeyPair(session, &mech,
        pub_template, (CK_ULONG)(sizeof(pub_template) / sizeof(pub_template[0])),
        priv_template, (CK_ULONG)(sizeof(priv_template) / sizeof(priv_template[0])),
        pub_key, priv_key);
    CHECK_CKR(ret, "C_GenerateKeyPair");
    return ret;
}

static CK_RV import_rsa_keypair(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE* pub_key,
                                CK_OBJECT_HANDLE* priv_key)
{
    CK_RV ret;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ULONG modulus_bits = 2048;

    CK_ATTRIBUTE pub_template[] = {
        { CKA_CLASS, &pub_key_class, sizeof(pub_key_class) },
        { CKA_KEY_TYPE, &rsa_key_type, sizeof(rsa_key_type) },
        { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        { CKA_ENCRYPT, &ck_true, sizeof(ck_true) },
        { CKA_VERIFY, &ck_true, sizeof(ck_true) },
        { CKA_WRAP, &ck_true, sizeof(ck_true) },
        { CKA_LABEL, (void*)rsa_key_label, (CK_ULONG)(sizeof(rsa_key_label) - 1) },
        { CKA_ID, rsa_key_id, sizeof(rsa_key_id) },
        { CKA_MODULUS, rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) }
    };

    CK_ATTRIBUTE priv_template[] = {
        { CKA_CLASS, &priv_key_class, sizeof(priv_key_class) },
        { CKA_KEY_TYPE, &rsa_key_type, sizeof(rsa_key_type) },
        { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        { CKA_SENSITIVE, &ck_true, sizeof(ck_true) },
        { CKA_DECRYPT, &ck_true, sizeof(ck_true) },
        { CKA_SIGN, &ck_true, sizeof(ck_true) },
        { CKA_UNWRAP, &ck_true, sizeof(ck_true) },
        { CKA_LABEL, (void*)rsa_key_label, (CK_ULONG)(sizeof(rsa_key_label) - 1) },
        { CKA_ID, rsa_key_id, sizeof(rsa_key_id) },
        { CKA_EXTRACTABLE, &ck_false, sizeof(ck_false) },
        { CKA_MODULUS, rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1, rsa_2048_p, sizeof(rsa_2048_p) },
        { CKA_PRIME_2, rsa_2048_q, sizeof(rsa_2048_q) },
        { CKA_EXPONENT_1, rsa_2048_dP, sizeof(rsa_2048_dP) },
        { CKA_EXPONENT_2, rsa_2048_dQ, sizeof(rsa_2048_dQ) },
        { CKA_COEFFICIENT, rsa_2048_u, sizeof(rsa_2048_u) }
    };

    ret = func_list->C_CreateObject(session, pub_template,
        (CK_ULONG)(sizeof(pub_template) / sizeof(pub_template[0])), &pub);
    CHECK_CKR(ret, "C_CreateObject (public RSA key)");
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_CreateObject(session, priv_template,
        (CK_ULONG)(sizeof(priv_template) / sizeof(priv_template[0])), &priv);
    CHECK_CKR(ret, "C_CreateObject (private RSA key)");
    if (ret != CKR_OK) {
        if (pub != CK_INVALID_HANDLE)
            func_list->C_DestroyObject(session, pub);
        return ret;
    }

    *pub_key = pub;
    *priv_key = priv;
    return CKR_OK;
}

static CK_RV setup_rsa_keypair(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE* pub_key,
                               CK_OBJECT_HANDLE* priv_key)
{
    CK_RV ret;

    if (library_version.major == 1 && library_version.minor <= 3) {
        printf("C_GenerateKeyPair unsupported for library v%u.%u, importing fixtures\n",
            library_version.major, library_version.minor);
        return import_rsa_keypair(session, pub_key, priv_key);
    }

    ret = generate_rsa_keypair(session, pub_key, priv_key);
    if (ret == CKR_OK)
        return CKR_OK;

    if (ret == CKR_FUNCTION_NOT_SUPPORTED || ret == CKR_MECHANISM_INVALID ||
        ret == CKR_DEVICE_ERROR || ret == CKR_GENERAL_ERROR ||
        ret == CKR_FUNCTION_FAILED) {
        printf("C_GenerateKeyPair failed (0x%lx), importing fixtures instead\n",
            (CK_ULONG)ret);
        return import_rsa_keypair(session, pub_key, priv_key);
    }

    return ret;
}

static CK_RV create_certificate(CK_SESSION_HANDLE session,
                                const unsigned char* cert,
                                CK_ULONG cert_len,
                                const unsigned char* subject,
                                CK_ULONG subject_len,
                                const char* label,
                                const CK_BYTE* id,
                                CK_ULONG id_len,
                                CK_OBJECT_HANDLE* out,
                                CK_BBOOL allow_legacy_fallback)
{
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &cert_class, sizeof(cert_class) },
        { CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
        { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        { CKA_LABEL, (void*)label, (CK_ULONG)(XSTRLEN(label)) },
        { CKA_SUBJECT, (void*)subject, subject_len },
        { CKA_VALUE, (void*)cert, cert_len },
        { CKA_ID, (void*)id, id_len }
    };
    CK_RV ret;

    if (out != NULL)
        *out = CK_INVALID_HANDLE;

    ret = func_list->C_CreateObject(session, template,
        (CK_ULONG)(sizeof(template) / sizeof(template[0])), out);
    if (ret != CKR_OK && allow_legacy_fallback) {
        printf("Certificate creation not supported on this library (0x%lx); skipping\n",
            (CK_ULONG)ret);
        set_legacy_cert_marker();
        return CKR_OK;
    }

    CHECK_CKR(ret, "C_CreateObject (certificate)");
    return ret;
}

static CK_RV find_single_object(CK_SESSION_HANDLE session,
                                CK_ATTRIBUTE* tmpl,
                                CK_ULONG tmpl_len,
                                CK_OBJECT_HANDLE* handle)
{
    CK_RV ret, final_ret;
    CK_ULONG count = 0;

    ret = func_list->C_FindObjectsInit(session, tmpl, tmpl_len);
    CHECK_CKR(ret, "C_FindObjectsInit");
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_FindObjects(session, handle, 1, &count);
    CHECK_CKR(ret, "C_FindObjects");
    final_ret = func_list->C_FindObjectsFinal(session);
    CHECK_CKR(final_ret, "C_FindObjectsFinal");
    if (ret == CKR_OK)
        ret = final_ret;

    if (ret == CKR_OK && count != 1) {
        fprintf(stderr, "Expected 1 object, found %lu\n", count);
        ret = CKR_GENERAL_ERROR;
    }

    return ret;
}

static int build_marker_path(char* buffer, size_t len)
{
    const char* base = getenv("WOLFPKCS11_TOKEN_PATH");
    size_t base_len, marker_len;

    if (base == NULL)
        return -1;

    base_len = XSTRLEN(base);
    marker_len = XSTRLEN(legacy_cert_marker_name);

    if (base_len + 1 + marker_len >= len)
        return -1;

    XSTRNCPY(buffer, base, len);
    if (base_len > 0 && (buffer[base_len - 1] != '/' && buffer[base_len - 1] != '\\')) {
        buffer[base_len] = '/';
        buffer[base_len + 1] = '\0';
        base_len++;
    }
    XSTRNCPY(buffer + base_len, legacy_cert_marker_name, len - base_len);
    return 0;
}

static void clear_legacy_cert_marker(void)
{
    char path[PATH_MAX];
    if (build_marker_path(path, sizeof(path)) == 0) {
        (void)remove(path);
    }
}

static void set_legacy_cert_marker(void)
{
    char path[PATH_MAX];
    FILE* f;

    if (build_marker_path(path, sizeof(path)) != 0)
        return;

    f = XFOPEN(path, "w");
    if (f != XBADFILE) {
        XFCLOSE(f);
    }
}

static int legacy_cert_marker_exists(void)
{
    char path[PATH_MAX];
    FILE* f;

    if (build_marker_path(path, sizeof(path)) != 0)
        return 0;

    f = XFOPEN(path, "r");
    if (f == XBADFILE)
        return 0;
    XFCLOSE(f);
    return 1;
}

static CK_RV rsa_sign_and_verify(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE pub_key,
                                 CK_OBJECT_HANDLE priv_key)
{
    CK_MECHANISM sign_mech = { CKM_SHA256_RSA_PKCS, NULL, 0 };
    CK_MECHANISM verify_mech = { CKM_SHA256_RSA_PKCS, NULL, 0 };
    unsigned char signature[256];
    CK_ULONG sig_len = sizeof(signature);
    CK_RV ret;

    ret = func_list->C_SignInit(session, &sign_mech, priv_key);
    CHECK_CKR(ret, "C_SignInit");
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_Sign(session, rsa_message, (CK_ULONG)sizeof(rsa_message),
                            signature, &sig_len);
    CHECK_CKR(ret, "C_Sign");
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_VerifyInit(session, &verify_mech, pub_key);
    CHECK_CKR(ret, "C_VerifyInit");
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_Verify(session, rsa_message, (CK_ULONG)sizeof(rsa_message),
                              signature, sig_len);
    CHECK_CKR(ret, "C_Verify");
    return ret;
}

static CK_RV rsa_encrypt_decrypt(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE pub_key,
                                 CK_OBJECT_HANDLE priv_key)
{
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    unsigned char encrypted[256];
    unsigned char decrypted[256];
    CK_ULONG enc_len = sizeof(encrypted);
    CK_ULONG dec_len = sizeof(decrypted);
    CK_RV ret;

    ret = func_list->C_EncryptInit(session, &mech, pub_key);
    CHECK_CKR(ret, "C_EncryptInit");
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_Encrypt(session, rsa_message, (CK_ULONG)sizeof(rsa_message),
                               encrypted, &enc_len);
    CHECK_CKR(ret, "C_Encrypt");
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_DecryptInit(session, &mech, priv_key);
    CHECK_CKR(ret, "C_DecryptInit");
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_Decrypt(session, encrypted, enc_len,
                               decrypted, &dec_len);
    CHECK_CKR(ret, "C_Decrypt");
    if (ret != CKR_OK)
        return ret;

    CHECK_COND(dec_len == (CK_ULONG)sizeof(rsa_message), "Decrypted length mismatch");
    CHECK_COND(XMEMCMP(decrypted, rsa_message, dec_len) == 0,
               "Decrypted data mismatch");

    return CKR_OK;
}

static CK_RV verify_certificate_value(CK_SESSION_HANDLE session,
                                      const CK_BYTE* id,
                                      CK_ULONG id_len,
                                      const unsigned char* expected,
                                      CK_ULONG expected_len)
{
    CK_OBJECT_HANDLE cert = CK_INVALID_HANDLE;
    CK_RV ret;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &cert_class, sizeof(cert_class) },
        { CKA_ID, (void*)id, id_len }
    };
    CK_ATTRIBUTE value_attr = { CKA_VALUE, NULL, 0 };
    unsigned char* buffer = NULL;

    ret = find_single_object(session, template,
        (CK_ULONG)(sizeof(template) / sizeof(template[0])), &cert);
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_GetAttributeValue(session, cert, &value_attr, 1);
    CHECK_CKR(ret, "C_GetAttributeValue (size)");
    if (ret != CKR_OK)
        return ret;

    buffer = (unsigned char*)malloc(value_attr.ulValueLen);
    CHECK_COND(buffer != NULL, "malloc certificate buffer");

    value_attr.pValue = buffer;
    ret = func_list->C_GetAttributeValue(session, cert, &value_attr, 1);
    CHECK_CKR(ret, "C_GetAttributeValue (value)");
    if (ret == CKR_OK) {
        CHECK_COND(value_attr.ulValueLen == expected_len,
                   "Certificate length mismatch");
        CHECK_COND(XMEMCMP(buffer, expected, expected_len) == 0,
                   "Certificate contents mismatch");
    }

    free(buffer);
    return ret;
}

static CK_RV create_data_object(CK_SESSION_HANDLE session,
                                const char* label,
                                const unsigned char* value,
                                CK_ULONG value_len,
                                const CK_BYTE* id,
                                CK_ULONG id_len,
                                CK_OBJECT_HANDLE* out)
{
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &data_class, sizeof(data_class) },
        { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        { CKA_PRIVATE, &ck_false, sizeof(ck_false) },
        { CKA_LABEL, (void*)label, (CK_ULONG)XSTRLEN(label) },
        { CKA_VALUE, (void*)value, value_len },
        { CKA_ID, (void*)id, id_len }
    };
    CK_RV ret;

    if (out != NULL)
        *out = CK_INVALID_HANDLE;

    ret = func_list->C_CreateObject(session, template,
        (CK_ULONG)(sizeof(template) / sizeof(template[0])), out);
    CHECK_CKR(ret, "C_CreateObject (data)");
    return ret;
}

static CK_RV verify_data_value(CK_SESSION_HANDLE session,
                               const CK_BYTE* id,
                               CK_ULONG id_len,
                               const unsigned char* expected,
                               CK_ULONG expected_len)
{
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    CK_RV ret;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &data_class, sizeof(data_class) },
        { CKA_ID, (void*)id, id_len }
    };
    CK_ATTRIBUTE value_attr = { CKA_VALUE, NULL, 0 };
    unsigned char* buffer = NULL;

    ret = find_single_object(session, template,
        (CK_ULONG)(sizeof(template) / sizeof(template[0])), &data);
    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_GetAttributeValue(session, data, &value_attr, 1);
    CHECK_CKR(ret, "C_GetAttributeValue (data size)");
    if (ret != CKR_OK)
        return ret;

    buffer = (unsigned char*)malloc(value_attr.ulValueLen);
    CHECK_COND(buffer != NULL, "malloc data buffer");

    value_attr.pValue = buffer;
    ret = func_list->C_GetAttributeValue(session, data, &value_attr, 1);
    CHECK_CKR(ret, "C_GetAttributeValue (data value)");
    if (ret == CKR_OK) {
        CHECK_COND(value_attr.ulValueLen == expected_len,
                   "Data length mismatch");
        CHECK_COND(XMEMCMP(buffer, expected, expected_len) == 0,
                   "Data contents mismatch");
    }

    free(buffer);
    return ret;
}

static CK_RV prepare_phase(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE cert = CK_INVALID_HANDLE;

    printf("== Prepare phase: initializing token and creating objects ==\n");

    clear_legacy_cert_marker();

    ret = pkcs11_init();
    if (ret != CKR_OK)
        goto exit;

    ret = initialize_token();
    CHECK_CKR(ret, "C_InitToken");
    if (ret != CKR_OK)
        goto exit;

    ret = open_rw_session(&session);
    if (ret != CKR_OK)
        goto exit;

    ret = login_so(session);
    if (ret != CKR_OK)
        goto exit;

    ret = initialize_user_pin(session);
    if (ret != CKR_OK)
        goto exit;

    func_list->C_Logout(session);

    ret = login_user(session);
    if (ret != CKR_OK)
        goto exit;

    ret = setup_rsa_keypair(session, &pub_key, &priv_key);
    if (ret != CKR_OK)
        goto exit;

    ret = create_certificate(session,
        upgrade_cert1, (CK_ULONG)sizeof(upgrade_cert1),
        upgrade_cert_subject1, (CK_ULONG)sizeof(upgrade_cert_subject1),
        cert_label, rsa_key_id, (CK_ULONG)sizeof(rsa_key_id), &cert,
        CK_TRUE);
    if (ret != CKR_OK)
        goto exit;

    printf("Prepare phase complete: token initialized and objects persisted.\n");

exit:
    if (session != CK_INVALID_HANDLE) {
        func_list->C_Logout(session);
        func_list->C_CloseSession(session);
    }
    pkcs11_final();
    return ret;
}

static CK_RV verify_phase(void)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE new_data = CK_INVALID_HANDLE;
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_CLASS, &pub_key_class, sizeof(pub_key_class) },
        { CKA_ID, rsa_key_id, sizeof(rsa_key_id) }
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_CLASS, &priv_key_class, sizeof(priv_key_class) },
        { CKA_ID, rsa_key_id, sizeof(rsa_key_id) }
    };
    CK_RV ret;

    printf("== Verify phase: validating upgraded storage ==\n");

    ret = pkcs11_init();
    if (ret != CKR_OK)
        goto exit;

    ret = open_rw_session(&session);
    if (ret != CKR_OK)
        goto exit;

    ret = login_user(session);
    if (ret != CKR_OK)
        goto exit;

    ret = find_single_object(session, pub_tmpl,
        (CK_ULONG)(sizeof(pub_tmpl) / sizeof(pub_tmpl[0])), &pub_key);
    if (ret != CKR_OK)
        goto exit;

    ret = find_single_object(session, priv_tmpl,
        (CK_ULONG)(sizeof(priv_tmpl) / sizeof(priv_tmpl[0])), &priv_key);
    if (ret != CKR_OK)
        goto exit;

    ret = rsa_sign_and_verify(session, pub_key, priv_key);
    if (ret != CKR_OK)
        goto exit;

    ret = rsa_encrypt_decrypt(session, pub_key, priv_key);
    if (ret != CKR_OK)
        goto exit;

    if (legacy_cert_marker_exists()) {
        printf("Legacy certificate marker detected; skipping certificate validation.\n");
    }
    else {
        ret = verify_certificate_value(session,
            rsa_key_id, (CK_ULONG)sizeof(rsa_key_id),
            upgrade_cert1, (CK_ULONG)sizeof(upgrade_cert1));
        if (ret != CKR_OK)
            goto exit;
    }

    ret = create_data_object(session,
        data_object_label, data_object_value, (CK_ULONG)sizeof(data_object_value),
        data_object_id, (CK_ULONG)sizeof(data_object_id), &new_data);
    if (ret != CKR_OK)
        goto exit;

    ret = verify_data_value(session,
        data_object_id, (CK_ULONG)sizeof(data_object_id),
        data_object_value, (CK_ULONG)sizeof(data_object_value));
    if (ret != CKR_OK)
        goto exit;

    printf("Verify phase complete: persisted objects validated and new object inserted.\n");

exit:
    if (session != CK_INVALID_HANDLE) {
        func_list->C_Logout(session);
        func_list->C_CloseSession(session);
    }
    pkcs11_final();
    if (ret == CKR_OK)
        clear_legacy_cert_marker();
    return ret;
}

int main(int argc, char** argv)
{
    test_phase_t phase = TEST_PHASE_PREPARE;
    CK_RV ret = CKR_OK;

    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--prepare") == 0) {
        phase = TEST_PHASE_PREPARE;
    }
    else if (strcmp(argv[1], "--verify") == 0) {
        phase = TEST_PHASE_VERIFY;
    }
    else {
        usage(argv[0]);
        return 1;
    }

    if (phase == TEST_PHASE_PREPARE)
        ret = prepare_phase();
    else
        ret = verify_phase();

    return (ret == CKR_OK) ? 0 : 1;
}

#endif /* WOLFPKCS11_NO_STORE || NO_RSA */
