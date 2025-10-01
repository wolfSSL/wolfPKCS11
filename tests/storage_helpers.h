/* storage_helpers.h
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

/* Lightweight helpers for tests that need to initialise wolfBoot-backed
 * storage without pulling in the full unit test harness.
 */

#ifndef TESTS_STORAGE_HELPERS_H
#define TESTS_STORAGE_HELPERS_H

#include <stdlib.h>

#if defined(__GNUC__)
    #define TESTS_UNUSED __attribute__((unused))
    #define TESTS_WEAK   __attribute__((weak))
#else
    #define TESTS_UNUSED
    #define TESTS_WEAK
#endif

#ifdef WOLFPKCS11_WOLFBOOT_STORE
    #include <wolfpkcs11/visibility.h>

    WP11_API int  wolfboot_store_test_init(const char* path) TESTS_WEAK;
    WP11_API void wolfboot_store_test_cleanup(void) TESTS_WEAK;
    WP11_API void wolfboot_store_test_reset(void) TESTS_WEAK;

    static inline TESTS_UNUSED int unit_init_storage(void)
    {
        static int cleanup_registered = 0;
        int ret = 0;

        if (wolfboot_store_test_init == NULL || wolfboot_store_test_reset == NULL)
            return 0;

        ret = wolfboot_store_test_init(NULL);

        if (ret != 0)
            return ret;

        wolfboot_store_test_reset();
        if (!cleanup_registered && wolfboot_store_test_cleanup != NULL) {
            atexit(wolfboot_store_test_cleanup);
            cleanup_registered = 1;
        }

        return 0;
    }

    static inline TESTS_UNUSED void unit_reset_storage(void)
    {
        if (wolfboot_store_test_reset != NULL)
            wolfboot_store_test_reset();
    }
#else
    static inline TESTS_UNUSED int unit_init_storage(void)
    {
        return 0;
    }

    static inline TESTS_UNUSED void unit_reset_storage(void)
    {
        (void)0;
    }
#endif

#endif /* TESTS_STORAGE_HELPERS_H */
