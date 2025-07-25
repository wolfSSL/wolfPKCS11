/* debug_test.c
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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifdef DEBUG_WOLFPKCS11
#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
static void* dlib = NULL;
void (*wolfPKCS11_Debugging_On_fp)(void) = NULL;
void (*wolfPKCS11_Debugging_Off_fp)(void) = NULL;
#endif

static CK_FUNCTION_LIST_PTR pFunctionList = NULL;

static FILE* original_stdout = NULL;
static FILE* capture_file = NULL;

static void setup_output_capture(void)
{
    original_stdout = stdout;
    capture_file = tmpfile();
    if (capture_file) {
        stdout = capture_file;
    }
}

static int check_debug_output(void)
{
    char buffer[1024];
    int found_debug = 0;

    if (!capture_file) {
        return 0;
    }

    stdout = original_stdout;
    rewind(capture_file);

    while (fgets(buffer, sizeof(buffer), capture_file)) {
        if (strstr(buffer, "WOLFPKCS11 ENTER:") ||
            strstr(buffer, "WOLFPKCS11 LEAVE:") ||
            strstr(buffer, "WOLFPKCS11:")) {
            found_debug = 1;
            break;
        }
    }

    fclose(capture_file);
    return found_debug;
}

/* Wrapper functions for debugging */
static void call_wolfPKCS11_Debugging_On(void) {
#ifndef HAVE_PKCS11_STATIC
    if (wolfPKCS11_Debugging_On_fp != NULL) {
        wolfPKCS11_Debugging_On_fp();
    }
#else
    wolfPKCS11_Debugging_On();
#endif
}

static void call_wolfPKCS11_Debugging_Off(void) {
#ifndef HAVE_PKCS11_STATIC
    if (wolfPKCS11_Debugging_Off_fp != NULL) {
        wolfPKCS11_Debugging_Off_fp();
    }
#else
    wolfPKCS11_Debugging_Off();
#endif
}

static CK_RV debug_init(const char* library) {
    CK_RV ret = CKR_OK;
#ifndef HAVE_PKCS11_STATIC
    void* func;

    dlib = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return -1;
    }

    func = (void*)(CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        return -1;
    }

    wolfPKCS11_Debugging_On_fp = (void (*)(void))dlsym(dlib,
                                                  "wolfPKCS11_Debugging_On");
    wolfPKCS11_Debugging_Off_fp = (void (*)(void))dlsym(dlib,
                                                 "wolfPKCS11_Debugging_Off");

    ret = ((CK_C_GetFunctionList)func)(&pFunctionList);
#else
    ret = C_GetFunctionList(&pFunctionList);
    (void)library;
#endif
    return ret;
}

static void debug_cleanup(void) {
#ifndef HAVE_PKCS11_STATIC
    if (dlib) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
}
#endif

int main(void)
{
#ifndef DEBUG_WOLFPKCS11
    printf("Debug mode is DISABLED (DEBUG_WOLFPKCS11 not defined)\n");
    printf("Skipping debug test - returning code 77\n");
    return 77;
#else
    CK_RV rv;
    int debug_found;
    const char* library = "./src/.libs/libwolfpkcs11.so";

#ifndef WOLFPKCS11_NO_ENV
    if (!XGETENV("WOLFPKCS11_TOKEN_PATH")) {
        XSETENV("WOLFPKCS11_TOKEN_PATH", "./store/debug", 1);
    }
#endif

    printf("=== wolfPKCS11 Debug Test Program ===\n");
    printf("Debug mode is ENABLED (DEBUG_WOLFPKCS11 defined)\n");

    printf("\nInitializing library:\n");
    rv = debug_init(library);
    if (rv != CKR_OK) {
        printf("Failed to initialize library: %lu\n", (unsigned long)rv);
        return 1;
    }

    printf("\nTesting debug control functions:\n");
    call_wolfPKCS11_Debugging_On();
    printf("Debug enabled\n");

    call_wolfPKCS11_Debugging_Off();
    printf("Debug disabled\n");

    call_wolfPKCS11_Debugging_On();
    printf("Debug re-enabled\n");

    printf("\nTesting PKCS#11 functions with debug output capture:\n");

    setup_output_capture();

    if (rv == CKR_OK && pFunctionList != NULL) {
        rv = pFunctionList->C_Initialize(NULL);

        if (rv == CKR_OK) {
            CK_INFO info;
            rv = pFunctionList->C_GetInfo(&info);
            pFunctionList->C_Finalize(NULL);
        }
    }

    debug_found = check_debug_output();

    printf("C_GetFunctionList returned: %lu\n", (unsigned long)rv);
    printf("Debug output detection: %s\n", debug_found ? "PASS" : "FAIL");

    call_wolfPKCS11_Debugging_Off();
    printf("Debug disabled at end\n");

    debug_cleanup();
    printf("\n=== Test Complete ===\n");

    if (!debug_found) {
        printf("ERROR: No debug output was detected during "
               "PKCS#11 function calls\n");
        return 1;
    }

    printf("SUCCESS: Debug output was properly generated\n");
    return 0;
#endif
}
