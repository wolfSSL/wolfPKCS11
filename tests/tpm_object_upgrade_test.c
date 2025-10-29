/* tpm_object_upgrade_test.c
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
 */

#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

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

#include <limits.h>
#ifndef PATH_MAX
    #define PATH_MAX 4096
#endif

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#include <glob.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(WOLFPKCS11_NO_STORE) && !defined(NO_RSA)

#include "testdata.h"

#define MAX_TRACKED_OBJECTS 10
#define DEFAULT_METADATA_FILE "tpm-upgrade-metadata.txt"

/* Helper macros mirroring other TPM regression tests */
#define CHECK_CKR(rv, msg)                                                 \
    do {                                                                   \
        if ((rv) != CKR_OK) {                                              \
            fprintf(stderr, "%s:%d: %s failed with 0x%lx\n",               \
                    __FILE__, __LINE__, (msg), (unsigned long)(rv));       \
        }                                                                  \
    }                                                                      \
    while (0)

#define CHECK_COND(cond, msg)                                              \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, (msg));     \
            return -1;                                                     \
        }                                                                  \
    }                                                                      \
    while (0)

typedef struct tpm_upgrade_options {
    int prepare;
    int verify;
    const char* module_path;
    const char* metadata_path;
    int verbose;
} tpm_upgrade_options;

typedef struct tpm_upgrade_counts {
    int key_count;
    int cert_count;
} tpm_upgrade_counts;

typedef CK_RV (*wolfPKCS11_TokenRepair_func)(CK_SLOT_ID, CK_FLAGS);
typedef void (*wolfPKCS11_Debugging_On_func)(void);
typedef void (*wolfPKCS11_Debugging_Off_func)(void);

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* func_list;
static wolfPKCS11_TokenRepair_func token_repair = NULL;
static wolfPKCS11_Debugging_On_func debug_on = NULL;
static wolfPKCS11_Debugging_Off_func debug_off = NULL;
static CK_SLOT_ID slot_id = 0;
static byte so_pin[] = "password123456";
static byte user_pin[] = "wolfpkcs11-test";
static const CK_ULONG so_pin_len = (CK_ULONG)(sizeof(so_pin) - 1);
static const CK_ULONG user_pin_len = (CK_ULONG)(sizeof(user_pin) - 1);
static const CK_UTF8CHAR token_label[] = "wolfPKCS11 TPM upgrade";

static CK_OBJECT_CLASS priv_key_class = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
static CK_CERTIFICATE_TYPE x509_cert_type = CKC_X_509;
static CK_KEY_TYPE rsa_key_type = CKK_RSA;
static CK_BBOOL ck_true = CK_TRUE;

static int verbose_log = 0;
static int debug_enabled = 0;
static char loaded_module_path[PATH_MAX];
static const char* loaded_module_path_ptr = NULL;

/* Simple X.509 certificate blob reused for all certificate objects. */
static const unsigned char rsa_cert_der[] = {
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

static void enable_debug_logging(void)
{
    if (debug_on != NULL && !debug_enabled) {
        debug_on();
        debug_enabled = 1;
    }
}

static void usage(const char* prog)
{
    fprintf(stderr,
        "Usage: %s (--prepare|--verify) [--module <path>] "
        "[--metadata-file <path>] [--verbose]\n", prog);
}

static int parse_args(int argc, char** argv, tpm_upgrade_options* opts)
{
    int i;

    XMEMSET(opts, 0, sizeof(*opts));
    opts->metadata_path = DEFAULT_METADATA_FILE;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--prepare") == 0) {
            opts->prepare = 1;
        }
        else if (strcmp(argv[i], "--verify") == 0) {
            opts->verify = 1;
        }
        else if (strcmp(argv[i], "--module") == 0) {
            if ((i + 1) >= argc) {
                usage(argv[0]);
                return -1;
            }
            opts->module_path = argv[++i];
        }
        else if (strcmp(argv[i], "--metadata-file") == 0) {
            if ((i + 1) >= argc) {
                usage(argv[0]);
                return -1;
            }
            opts->metadata_path = argv[++i];
        }
        else if (strcmp(argv[i], "--verbose") == 0) {
            opts->verbose = 1;
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return -1;
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return -1;
        }
    }

    if (opts->prepare == opts->verify) {
        fprintf(stderr, "Exactly one of --prepare or --verify must be set\n");
        usage(argv[0]);
        return -1;
    }

    if (opts->module_path == NULL) {
        opts->module_path = WOLFPKCS11_DLL_FILENAME;
    }

    verbose_log = opts->verbose;

    return 0;
}

#define verbose_printf(...)                                                \
    do {                                                                   \
        if (verbose_log)                                                   \
            printf(__VA_ARGS__);                                           \
    } while (0)

static void* pkcs11_open_module_handle(const char* module_path)
{
    void* handle = NULL;

#if defined(LM_ID_NEWLM)
    /* Prefer a fresh namespace so we never reuse a previously-loaded copy. */
    dlerror();
    handle = dlmopen(LM_ID_NEWLM, module_path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        const char* err = dlerror();
        if (verbose_log && err != NULL) {
            fprintf(stderr,
                "dlmopen failed for %s: %s (falling back to dlopen)\n",
                module_path, err);
        }
    }
#endif

    if (handle == NULL) {
        dlerror();
        handle = dlopen(module_path, RTLD_NOW | RTLD_LOCAL);
    }

    return handle;
}

static void log_module_version(const char* module_path)
{
    CK_INFO info;
    CK_RV rv;
    const char* path = module_path != NULL ? module_path : "(unknown)";

    if (func_list == NULL || func_list->C_GetInfo == NULL)
        return;

    XMEMSET(&info, 0, sizeof(info));
    rv = func_list->C_GetInfo(&info);
    if (rv == CKR_OK) {
        printf("Loaded %s (libraryVersion %u.%u)\n", path,
            (unsigned int)info.libraryVersion.major,
            (unsigned int)info.libraryVersion.minor);
    }
    else {
        fprintf(stderr, "C_GetInfo failed for %s: 0x%lx\n", path,
            (unsigned long)rv);
    }
}

static void remember_module_path(const char* module_path)
{
    if (module_path != NULL) {
        size_t len = strlen(module_path);
        if (len >= sizeof(loaded_module_path))
            len = sizeof(loaded_module_path) - 1;
        memcpy(loaded_module_path, module_path, len);
        loaded_module_path[len] = '\0';
        loaded_module_path_ptr = loaded_module_path;
    }
    else {
        loaded_module_path_ptr = NULL;
    }
}

static CK_RV pkcs11_load_module(const char* module_path)
{
    CK_RV ret = CKR_OK;
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func = NULL;
    const char* resolved_path = module_path;
    char resolved_path_buf[PATH_MAX];
    resolved_path_buf[0] = '\0';

    dlib = pkcs11_open_module_handle(module_path);
    if (dlib == NULL) {
        glob_t matches;
        char pattern[PATH_MAX];

        if (strlen(module_path) < sizeof(pattern) - 2) {
            snprintf(pattern, sizeof(pattern), "%s*", module_path);
            if (glob(pattern, 0, NULL, &matches) == 0) {
                size_t i;
                for (i = 0; i < matches.gl_pathc; i++) {
                    const char* candidate = matches.gl_pathv[i];
                    if (strcmp(candidate, module_path) == 0)
                        continue;
                    dlib = pkcs11_open_module_handle(candidate);
                    if (dlib != NULL) {
                        snprintf(resolved_path_buf, sizeof(resolved_path_buf),
                            "%s", candidate);
                        resolved_path = resolved_path_buf;
                        break;
                    }
                }
            }
            globfree(&matches);
        }
    }

    if (dlib == NULL) {
        fprintf(stderr, "dlopen failed for %s: %s\n",
            module_path, dlerror());
        return CKR_GENERAL_ERROR;
    }

    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "dlsym(C_GetFunctionList) failed\n");
        dlclose(dlib);
        dlib = NULL;
        return CKR_GENERAL_ERROR;
    }

    ret = func(&func_list);
    if (ret == CKR_OK && func_list != NULL) {
        Dl_info info;
        if (dladdr((void*)func, &info) != 0 && info.dli_fname != NULL) {
            remember_module_path(info.dli_fname);
        }
        else {
            if (resolved_path == module_path && module_path != NULL &&
                resolved_path_buf[0] == '\0') {
                snprintf(resolved_path_buf, sizeof(resolved_path_buf), "%s",
                    module_path);
                resolved_path = resolved_path_buf;
            }
            remember_module_path(resolved_path);
        }
        token_repair = (wolfPKCS11_TokenRepair_func)dlsym(dlib,
            "wolfPKCS11_TokenRepair");
        debug_on = (wolfPKCS11_Debugging_On_func)dlsym(dlib,
            "wolfPKCS11_Debugging_On");
        debug_off = (wolfPKCS11_Debugging_Off_func)dlsym(dlib,
            "wolfPKCS11_Debugging_Off");
    }
#else
    (void)module_path;
    ret = C_GetFunctionList(&func_list);
    if (ret == CKR_OK && func_list != NULL) {
        remember_module_path("libwolfpkcs11 (static link)");
        token_repair = wolfPKCS11_TokenRepair;
    #ifdef DEBUG_WOLFPKCS11
        debug_on = wolfPKCS11_Debugging_On;
        debug_off = wolfPKCS11_Debugging_Off;
    #else
        debug_on = NULL;
        debug_off = NULL;
    #endif
    }
#endif
    CHECK_CKR(ret, "C_GetFunctionList");
    return ret;
}

static void pkcs11_unload_module(int finalize)
{
    if (finalize && func_list != NULL) {
        func_list->C_Finalize(NULL);
    }
    if (debug_off != NULL && debug_enabled)
        debug_off();
    debug_enabled = 0;
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
    func_list = NULL;
    token_repair = NULL;
    debug_on = NULL;
    debug_off = NULL;
}

static CK_RV pkcs11_initialize(void)
{
    CK_C_INITIALIZE_ARGS args;
    CK_RV ret;
    CK_SLOT_ID slots[8];
    CK_ULONG slot_count = sizeof(slots) / sizeof(slots[0]);

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;

    ret = func_list->C_Initialize(&args);
    if (ret == CKR_OK)
        enable_debug_logging();
    if (ret == CKR_WOLFPKCS11_TOKEN_REPAIR_NEEDED) {
        verbose_printf("C_Initialize reported CKR_WOLFPKCS11_TOKEN_REPAIR_NEEDED\n");
        if (token_repair == NULL) {
            fprintf(stderr, "wolfPKCS11_TokenRepair not available in module\n");
            return ret;
        }
        enable_debug_logging();
        ret = token_repair(1, 0);
        CHECK_CKR(ret, "wolfPKCS11_TokenRepair");
        if (ret != CKR_OK)
            return ret;
        ret = func_list->C_Initialize(&args);
        if (ret == CKR_OK)
            enable_debug_logging();
    }
    CHECK_CKR(ret, "C_Initialize");

    if (ret == CKR_OK)
        log_module_version(loaded_module_path_ptr);

    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_GetSlotList(CK_TRUE, slots, &slot_count);
    CHECK_CKR(ret, "C_GetSlotList");
    if (ret != CKR_OK)
        return ret;

    if (slot_count == 0) {
        fprintf(stderr, "No slots available\n");
        return CKR_GENERAL_ERROR;
    }

    slot_id = slots[0];
    verbose_printf("Using slot %lu\n", (unsigned long)slot_id);

    return CKR_OK;
}

static CK_RV init_token_if_needed(void)
{
    CK_RV ret;
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, token_label,
        XSTRLEN((const char*)token_label) < (int)sizeof(label) ?
            XSTRLEN((const char*)token_label) : (int)sizeof(label));

    ret = func_list->C_InitToken(slot_id, so_pin, so_pin_len, label);
    if (ret == CKR_PIN_INCORRECT || ret == CKR_SESSION_EXISTS) {
        /* Already initialised, treat as success */
        verbose_printf("Token already initialised (0x%lx)\n", (unsigned long)ret);
        ret = CKR_OK;
    }
    CHECK_CKR(ret, "C_InitToken");
    return ret;
}

static CK_RV set_user_pin(void)
{
    CK_SESSION_HANDLE session;
    CK_RV ret;

    ret = func_list->C_OpenSession(slot_id,
        CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession");

    if (ret != CKR_OK)
        return ret;

    ret = func_list->C_Login(session, CKU_SO, so_pin, so_pin_len);
    if (ret == CKR_OK) {
        ret = func_list->C_InitPIN(session, user_pin, user_pin_len);
        CHECK_CKR(ret, "C_InitPIN");
        func_list->C_Logout(session);
    }
    else if (ret == CKR_USER_ALREADY_LOGGED_IN) {
        verbose_printf("SO already logged in\n");
        ret = CKR_OK;
    }
    else if (ret == CKR_PIN_INCORRECT) {
        verbose_printf("SO PIN already set\n");
        ret = CKR_OK;
    }
    else {
        CHECK_CKR(ret, "SO login during InitPIN");
    }

    func_list->C_CloseSession(session);
    return ret;
}

static CK_RV open_user_session(CK_SESSION_HANDLE* session, int rw)
{
    CK_RV ret;
    CK_FLAGS flags = CKF_SERIAL_SESSION;

    if (rw)
        flags |= CKF_RW_SESSION;

    ret = func_list->C_OpenSession(slot_id, flags, NULL, NULL, session);
    CHECK_CKR(ret, "C_OpenSession");
    if (ret != CKR_OK)
        return ret;

    if (token_repair == NULL)
        verbose_printf("Token repair callback not available\n");

    ret = func_list->C_Login(*session, CKU_USER, user_pin, user_pin_len);
    if (ret == CKR_USER_ALREADY_LOGGED_IN) {
        verbose_printf("User already logged in\n");
        ret = CKR_OK;
    }
    else if ((ret == CKR_PIN_INCORRECT ||
              ret == CKR_USER_PIN_NOT_INITIALIZED) &&
             token_repair != NULL) {
        verbose_printf("User login failed, attempting token repair...\n");
        CHECK_CKR(token_repair(slot_id, 0), "wolfPKCS11_TokenRepair");
        ret = func_list->C_Login(*session, CKU_USER, user_pin, user_pin_len);
        CHECK_CKR(ret, "C_Login");
    }
    else {
        CHECK_CKR(ret, "C_Login");
    }

    if (ret != CKR_OK) {
        func_list->C_CloseSession(*session);
        *session = CK_INVALID_HANDLE;
    }

    return ret;
}

static void close_user_session(CK_SESSION_HANDLE session)
{
    if (session != CK_INVALID_HANDLE) {
        func_list->C_Logout(session);
        func_list->C_CloseSession(session);
    }
}

static CK_RV create_rsa_private_key(CK_SESSION_HANDLE session, int index)
{
    CK_RV ret;
    (void)index; /* Unique attributes not supported on legacy versions */
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS,            &priv_key_class,        sizeof(priv_key_class)        },
        { CKA_KEY_TYPE,         &rsa_key_type,          sizeof(rsa_key_type)          },
        { CKA_TOKEN,            &ck_true,               sizeof(ck_true)               },
        { CKA_PRIVATE,          &ck_true,               sizeof(ck_true)               },
        { CKA_DECRYPT,          &ck_true,               sizeof(ck_true)               },
        { CKA_SIGN,             &ck_true,               sizeof(ck_true)               },
        { CKA_MODULUS,          rsa_2048_modulus,       sizeof(rsa_2048_modulus)      },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp,      sizeof(rsa_2048_priv_exp)     },
        { CKA_PRIME_1,          rsa_2048_p,             sizeof(rsa_2048_p)            },
        { CKA_PRIME_2,          rsa_2048_q,             sizeof(rsa_2048_q)            },
        { CKA_EXPONENT_1,       rsa_2048_dP,            sizeof(rsa_2048_dP)           },
        { CKA_EXPONENT_2,       rsa_2048_dQ,            sizeof(rsa_2048_dQ)           },
        { CKA_COEFFICIENT,      rsa_2048_u,             sizeof(rsa_2048_u)            },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,       sizeof(rsa_2048_pub_exp)      }
    };

    ret = func_list->C_CreateObject(session, template,
        (CK_ULONG)(sizeof(template)/sizeof(CK_ATTRIBUTE)), &handle);

    if (ret == CKR_DEVICE_MEMORY || ret == CKR_HOST_MEMORY ||
        ret == CKR_FUNCTION_FAILED) {
        verbose_printf("TPM memory exhausted while creating key %d\n", index);
    }
    else if (ret != CKR_OK) {
        CHECK_CKR(ret, "Create RSA private key");
    }
    return ret;
}

static CK_RV create_certificate(CK_SESSION_HANDLE session, int index)
{
    CK_RV ret;
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS,            &cert_class,            sizeof(cert_class)            },
        { CKA_CERTIFICATE_TYPE, &x509_cert_type,        sizeof(x509_cert_type)        },
        { CKA_TOKEN,            &ck_true,               sizeof(ck_true)               },
        { CKA_VALUE,            (void*)rsa_cert_der,    sizeof(rsa_cert_der)          }
    };

    ret = func_list->C_CreateObject(session, template,
        (CK_ULONG)(sizeof(template)/sizeof(CK_ATTRIBUTE)), &handle);
    if (ret == CKR_DEVICE_MEMORY || ret == CKR_HOST_MEMORY ||
        ret == CKR_FUNCTION_FAILED) {
        verbose_printf("TPM memory exhausted while creating cert %d\n", index);
    }
    else if (ret != CKR_OK) {
        CHECK_CKR(ret, "Create certificate");
    }
    return ret;
}

static int write_metadata(const char* path, const tpm_upgrade_counts* counts)
{
    FILE* file;

    file = fopen(path, "w");
    if (file == NULL) {
        fprintf(stderr, "Failed to open metadata file %s for writing: %s\n",
            path, strerror(errno));
        return -1;
    }

    if (fprintf(file, "%d %d\n", counts->key_count, counts->cert_count) < 0) {
        fprintf(stderr, "Failed to write metadata\n");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

static int read_metadata(const char* path, tpm_upgrade_counts* counts)
{
    FILE* file;

    file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "Failed to open metadata file %s: %s\n",
            path, strerror(errno));
        return -1;
    }

    if (fscanf(file, "%d %d", &counts->key_count,
            &counts->cert_count) != 2) {
        fprintf(stderr, "Invalid metadata file format\n");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

static CK_RV prepare_objects(const tpm_upgrade_options* opts)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    tpm_upgrade_counts counts;
    int i;

    counts.key_count = 0;
    counts.cert_count = 0;

    ret = init_token_if_needed();
    if (ret != CKR_OK)
        return ret;

    ret = set_user_pin();
    if (ret != CKR_OK)
        return ret;

    ret = open_user_session(&session, 1);
    if (ret != CKR_OK)
        return ret;

    for (i = 0; i < MAX_TRACKED_OBJECTS; i++) {
        ret = create_rsa_private_key(session, i);
        if (ret == CKR_OK) {
            counts.key_count++;
        }
        else if (ret == CKR_DEVICE_MEMORY || ret == CKR_HOST_MEMORY ||
                 ret == CKR_FUNCTION_FAILED) {
            continue;
        }
        else {
            close_user_session(session);
            return ret;
        }

        ret = create_certificate(session, i);
        if (ret == CKR_OK) {
            counts.cert_count++;
        }
        else if (ret == CKR_DEVICE_MEMORY || ret == CKR_HOST_MEMORY ||
                 ret == CKR_FUNCTION_FAILED) {
            continue;
        }
        else {
            close_user_session(session);
            return ret;
        }
    }

    verbose_printf("Prepared %d private keys and %d public keys\n",
        counts.key_count, counts.cert_count);

    if (write_metadata(opts->metadata_path, &counts) != 0)
        return CKR_GENERAL_ERROR;

    return CKR_OK;
}

static CK_RV count_objects_by_class(CK_SESSION_HANDLE session,
    CK_OBJECT_CLASS cls, CK_ULONG* total_out)
{
    CK_RV ret;
    CK_OBJECT_HANDLE sample = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE handles[16];
    CK_ULONG total = 0;
    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, (void*)&cls, sizeof(cls) },
        { CKA_TOKEN, (void*)&ck_true, sizeof(ck_true) }
    };

    ret = func_list->C_FindObjectsInit(session, template,
        (CK_ULONG)(sizeof(template)/sizeof(CK_ATTRIBUTE)));
    CHECK_CKR(ret, "C_FindObjectsInit");
    if (ret != CKR_OK)
        return ret;

    for (;;) {
        CK_ULONG count = 0;

        ret = func_list->C_FindObjects(session, handles,
            (CK_ULONG)(sizeof(handles)/sizeof(handles[0])), &count);
        CHECK_CKR(ret, "C_FindObjects");
        if (ret != CKR_OK)
            break;

        if (count > 0 && sample == CK_INVALID_HANDLE)
            sample = handles[0];

        total += count;

        if (count == 0)
            break;
    }

    {
        CK_RV final_ret = func_list->C_FindObjectsFinal(session);
        CHECK_CKR(final_ret, "C_FindObjectsFinal");
        if (ret == CKR_OK && final_ret != CKR_OK)
            ret = final_ret;
    }

    if (ret == CKR_OK) {
        *total_out = total;

        if (sample != CK_INVALID_HANDLE) {
            CK_OBJECT_CLASS class_value;
            CK_ATTRIBUTE attr = {
                CKA_CLASS, (void*)&class_value, sizeof(class_value)
            };

            ret = func_list->C_GetAttributeValue(session, sample, &attr, 1);
            CHECK_CKR(ret, "C_GetAttributeValue");
        }
    }

    return ret;
}

static CK_RV verify_objects(const tpm_upgrade_options* opts)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    tpm_upgrade_counts counts;
    CK_ULONG key_total = 0;
    CK_ULONG cert_total = 0;

    if (read_metadata(opts->metadata_path, &counts) != 0)
        return CKR_GENERAL_ERROR;

    ret = open_user_session(&session, 0);
    if (ret != CKR_OK)
        return ret;

    ret = count_objects_by_class(session, CKO_PRIVATE_KEY, &key_total);
    if (ret == CKR_OK && key_total != (CK_ULONG)counts.key_count) {
        fprintf(stderr, "Expected %d private keys, found %lu\n",
            counts.key_count, (unsigned long)key_total);
        ret = CKR_GENERAL_ERROR;
    }

    if (ret == CKR_OK) {
        ret = count_objects_by_class(session, cert_class, &cert_total);
        if (ret == CKR_OK && cert_total != (CK_ULONG)counts.cert_count) {
            fprintf(stderr, "Expected %d public keys, found %lu\n",
                counts.cert_count, (unsigned long)cert_total);
            ret = CKR_GENERAL_ERROR;
        }
    }

    close_user_session(session);

    return ret;
}

static const char* resolve_metadata_path(const tpm_upgrade_options* opts,
    char* buffer, size_t buffer_len)
{
    const char* token_path = getenv("WOLFPKCS11_TOKEN_PATH");

    if (opts->metadata_path != NULL &&
        opts->metadata_path[0] == '/') {
        return opts->metadata_path;
    }

    if (token_path != NULL && buffer != NULL) {
        size_t len = strlen(token_path);
        int need_sep = (len > 0 && token_path[len - 1] != '/') ? 1 : 0;

        if (snprintf(buffer, buffer_len, "%s%s%s",
                token_path, need_sep ? "/" : "",
                opts->metadata_path) >= (int)buffer_len) {
            fprintf(stderr, "Metadata path buffer too small\n");
            return NULL;
        }
        return buffer;
    }

    return opts->metadata_path;
}

int main(int argc, char** argv)
{
    tpm_upgrade_options opts;
    CK_RV ret;
    int exit_code = EXIT_FAILURE;
    char metadata_path[512];
    const char* resolved_metadata;

    if (argc == 1) {
        fprintf(stderr,
            "tpm_object_upgrade_test: requires --prepare or --verify (skipping)\n");
        return 77;
    }

    if (parse_args(argc, argv, &opts) != 0)
        return EXIT_FAILURE;

    resolved_metadata = resolve_metadata_path(&opts, metadata_path,
        sizeof(metadata_path));
    if (resolved_metadata == NULL)
        return EXIT_FAILURE;
    opts.metadata_path = resolved_metadata;

    if (pkcs11_load_module(opts.module_path) != CKR_OK)
        return EXIT_FAILURE;

    ret = pkcs11_initialize();
    if (ret != CKR_OK) {
        pkcs11_unload_module(0);
        return EXIT_FAILURE;
    }

    if (opts.prepare) {
        ret = prepare_objects(&opts);
    }
    else {
        ret = verify_objects(&opts);
    }

    if (ret == CKR_OK) {
        exit_code = EXIT_SUCCESS;
    }
    else {
        fprintf(stderr, "TPM object upgrade test failed with 0x%lx\n",
            (unsigned long)ret);
    }

    pkcs11_unload_module(opts.prepare ? 0 : 1);

    return exit_code;
}

#else

int main(void)
{
    fprintf(stderr, "TPM object upgrade test requires RSA and storage support\n");
    return 77; /* skipped */
}

#endif /* !WOLFPKCS11_NO_STORE && !NO_RSA */
#include <wolfssl/wolfcrypt/memory.h>
