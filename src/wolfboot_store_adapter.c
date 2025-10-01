/* wolfboot_store_adapter.c
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

/* Adapter that pulls in wolfBoot's PKCS#11 storage implementation so it can
 * satisfy the wolfPKCS11 custom store API when built for host-based testing.
 *
 * The implementation mirrors the wolfBoot unit test harness by defining the
 * storage backing as an in-memory flash image. The wolfBoot source tree is
 * expected to be provided at configure time via --with-wolfboot so the
 * pkcs11_store.c source can be included directly.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <wolfpkcs11/visibility.h>
#include <wolfpkcs11/store.h>
#include <sys/mman.h>

WP11_API int wolfboot_store_test_init(const char* path);
WP11_API void wolfboot_store_test_reset(void);
WP11_API void wolfboot_store_test_cleanup(void);

/* Ensure the wolfBoot store compiles in test mode and without hardware
 * dependencies. */
#ifndef UNIT_TEST
    #define UNIT_TEST
#endif
#ifndef SECURE_PKCS11
    #define SECURE_PKCS11
#endif
#ifndef MOCK_PARTITIONS
    #define MOCK_PARTITIONS
#endif
#ifndef MOCK_KEYVAULT
    #define MOCK_KEYVAULT
#endif
#if !defined(ARCH_x86_64) && defined(__x86_64__)
    #define ARCH_x86_64
#endif
#if !defined(ARCH_aarch64) && defined(__aarch64__)
    #define ARCH_aarch64
#endif
#if !defined(ARCH_64BIT) && (defined(ARCH_x86_64) || defined(ARCH_aarch64))
    #define ARCH_64BIT
#endif

#include <wolfssl/options.h>

#ifndef __has_include
    #define __has_include(x) 0
#endif

#if __has_include(<hal.h>)
    #include <hal.h>
#else
    typedef uintptr_t haladdr_t;
#endif

/* wolfBoot's pkcs11_store.c expects this symbol when compiled with
 * UNIT_TEST. */
static const uintptr_t wolfboot_vault_addr = 0xCF000000UL;

uint8_t* vault_base = NULL;

static uint8_t* wolfboot_store_region = NULL;
static size_t wolfboot_store_region_sz = 0;
static int wolfboot_flash_locked = 1;
static int wolfboot_store_mapped = 0;

static const char* wolfboot_store_backing_path(void)
{
    static char path[PATH_MAX];
    static int initialized = 0;
    const char* token_path;

    if (!initialized) {
        token_path = getenv("WOLFPKCS11_TOKEN_PATH");
        if (token_path != NULL && token_path[0] != '\0') {
            size_t len = strlen(token_path);
            int need_sep = (len > 0 && token_path[len - 1] != '/') ? 1 : 0;

            if ((size_t)snprintf(path, sizeof(path), "%s%s%s", token_path,
                    need_sep ? "/" : "", "wolfboot_store.bin") < sizeof(path)) {
                initialized = 1;
            }
        }
        if (!initialized) {
            (void)snprintf(path, sizeof(path), "%s", "/tmp/wolfboot_store.bin");
            initialized = 1;
        }
    }

    return path;
}

static int wolfboot_store_mkdir_p(const char* dir)
{
    char tmp[PATH_MAX];
    size_t len;
    char* p;

    if (dir == NULL)
        return -1;

    len = strlen(dir);
    if (len == 0 || len >= sizeof(tmp))
        return -1;

    memcpy(tmp, dir, len + 1);
    for (p = tmp + 1; *p != '\0'; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }

    if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
        return -1;

    return 0;
}

static void wolfboot_store_ensure_backing_dir(const char* file_path)
{
    const char* slash;
    size_t dir_len;
    char dir[PATH_MAX];

    if (file_path == NULL)
        return;

    slash = strrchr(file_path, '/');
    if (slash == NULL)
        return;

    dir_len = (size_t)(slash - file_path);
    if (dir_len == 0 || dir_len >= sizeof(dir))
        return;

    memcpy(dir, file_path, dir_len);
    dir[dir_len] = '\0';

    (void)wolfboot_store_mkdir_p(dir);
}

static void wolfboot_store_flush(void)
{
    const char* path;
    FILE* file;

    if (vault_base == NULL || wolfboot_store_region_sz == 0)
        return;

    path = wolfboot_store_backing_path();
    wolfboot_store_ensure_backing_dir(path);
    file = fopen(path, "wb");
    if (file == NULL)
        return;

    (void)fwrite(vault_base, 1, wolfboot_store_region_sz, file);
    (void)fflush(file);
    fclose(file);
}

static void wolfboot_store_load(void)
{
    const char* path;
    FILE* file;
    size_t read_sz;

    if (vault_base == NULL || wolfboot_store_region_sz == 0)
        return;

    path = wolfboot_store_backing_path();
    file = fopen(path, "rb");
    if (file == NULL)
        return;

    read_sz = fread(vault_base, 1, wolfboot_store_region_sz, file);
    if (read_sz < wolfboot_store_region_sz) {
        memset(vault_base + read_sz, 0xFF,
            wolfboot_store_region_sz - read_sz);
    }
    fclose(file);
}

static int wolfboot_address_valid(uintptr_t address, size_t len)
{
    const uint8_t* start = (const uint8_t*)address;
    const uint8_t* end;

    if (wolfboot_store_region == NULL || len == 0)
        return 0;

    end = start + len;
    return (start >= wolfboot_store_region) &&
           (end <= wolfboot_store_region + wolfboot_store_region_sz);
}

void hal_init(void)
{
}

void hal_prepare_boot(void)
{
}

void hal_flash_unlock(void)
{
    wolfboot_flash_locked = 0;
}

void hal_flash_lock(void)
{
    wolfboot_flash_locked = 1;
}

int hal_flash_erase(haladdr_t address, int len)
{
    if (wolfboot_flash_locked || len <= 0)
        return -1;
    if (!wolfboot_address_valid((uintptr_t)address, (size_t)len))
        return -1;

    memset((void*)(uintptr_t)address, 0xFF, (size_t)len);
    return 0;
}

int hal_flash_write(haladdr_t address, const uint8_t* data, int len)
{
    if (wolfboot_flash_locked || len <= 0 || data == NULL)
        return -1;
    if (!wolfboot_address_valid((uintptr_t)address, (size_t)len))
        return -1;

    memcpy((void*)(uintptr_t)address, data, (size_t)len);
    return 0;
}

/* Suppress warnings from the wolfBoot sources pulled in below. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#endif

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-compare"
#ifndef __clang__
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#pragma GCC diagnostic ignored "-Wcpp"
#endif

static int wolfBoot_Store_Open_impl(int type, CK_ULONG id1, CK_ULONG id2,
    int read, void** store);
static void wolfBoot_Store_Close_impl(void* store);
static int wolfBoot_Store_Read_impl(void* store, unsigned char* buffer,
    int len);
static int wolfBoot_Store_Write_impl(void* store, unsigned char* buffer,
    int len);
static int wolfBoot_Store_Remove_impl(int type, CK_ULONG id1, CK_ULONG id2);

#define wolfPKCS11_Store_Open   wolfBoot_Store_Open_impl
#define wolfPKCS11_Store_Close  wolfBoot_Store_Close_impl
#define wolfPKCS11_Store_Read   wolfBoot_Store_Read_impl
#define wolfPKCS11_Store_Write  wolfBoot_Store_Write_impl
#define wolfPKCS11_Store_Remove wolfBoot_Store_Remove_impl

/* Pull in the wolfBoot PKCS#11 storage implementation. The include path is
 * provided by configure's --with-wolfboot option. */
#include "pkcs11_store.c" /* NOLINT(bugprone-suspicious-include) */

#undef wolfPKCS11_Store_Open
#undef wolfPKCS11_Store_Close
#undef wolfPKCS11_Store_Read
#undef wolfPKCS11_Store_Write
#undef wolfPKCS11_Store_Remove

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

static void wolfboot_store_ensure_init(void)
{
    if (wolfboot_store_region == NULL)
        (void)wolfboot_store_test_init(NULL);
}

WP11_LOCAL int wolfPKCS11_Store_Remove(int type, CK_ULONG id1, CK_ULONG id2)
{
    wolfboot_store_ensure_init();
    return wolfBoot_Store_Remove_impl(type, id1, id2);
}

WP11_LOCAL int wolfPKCS11_Store_Open(int type, CK_ULONG id1, CK_ULONG id2,
    int read, void** store)
{
    wolfboot_store_ensure_init();
    return wolfBoot_Store_Open_impl(type, id1, id2, read, store);
}

WP11_LOCAL void wolfPKCS11_Store_Close(void* store)
{
    wolfBoot_Store_Close_impl(store);
}

static int wolfboot_sector_valid(struct store_handle* handle)
{
    uintptr_t addr;
    uint32_t offset;

    if (handle == NULL || handle->buffer == NULL)
        return 0;

    offset = ((uintptr_t)handle->buffer + handle->in_buffer_offset) %
        WOLFBOOT_SECTOR_SIZE;
    addr = (uintptr_t)handle->buffer + handle->in_buffer_offset - offset;

    return wolfboot_address_valid(addr, WOLFBOOT_SECTOR_SIZE);
}

WP11_LOCAL int wolfPKCS11_Store_Read(void* store, unsigned char* buffer,
    int len)
{
    struct store_handle* handle = (struct store_handle*)store;

    wolfboot_store_ensure_init();
    if (!wolfboot_sector_valid(handle))
        return NOT_AVAILABLE_E;

    return wolfBoot_Store_Read_impl(store, buffer, len);
}

WP11_LOCAL int wolfPKCS11_Store_Write(void* store, unsigned char* buffer,
    int len)
{
    struct store_handle* handle = (struct store_handle*)store;
    int ret;

    wolfboot_store_ensure_init();
    if (!wolfboot_sector_valid(handle))
        return NOT_AVAILABLE_E;

    ret = wolfBoot_Store_Write_impl(store, buffer, len);
    if (ret >= 0)
        wolfboot_store_flush();
    return ret;
}

static size_t wolfboot_store_calc_size(void)
{
    size_t objects = (size_t)KEYVAULT_MAX_ITEMS * (size_t)KEYVAULT_OBJ_SIZE;
    size_t overhead = (size_t)WOLFBOOT_SECTOR_SIZE * 2;
    return objects + overhead;
}

WP11_API int wolfboot_store_test_init(const char* path)
{
    (void)path;

    if (vault_base != NULL)
        return 0;

    wolfboot_store_region_sz = wolfboot_store_calc_size();
    wolfboot_store_region = (uint8_t*)mmap((void*)wolfboot_vault_addr,
        wolfboot_store_region_sz, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (wolfboot_store_region == MAP_FAILED) {
        wolfboot_store_region = (uint8_t*)malloc(wolfboot_store_region_sz);
        if (wolfboot_store_region == NULL)
            return -ENOMEM;
        wolfboot_store_mapped = 0;
    }
    else {
        wolfboot_store_mapped = 1;
    }

    vault_base = wolfboot_store_region;
    memset(vault_base, 0xFF, wolfboot_store_region_sz);
    wolfboot_store_load();
    wolfboot_flash_locked = 1;

    return 0;
}

WP11_API void wolfboot_store_test_reset(void)
{
    if (vault_base != NULL) {
        memset(vault_base, 0xFF, wolfboot_store_region_sz);
        wolfboot_store_flush();
    }
    wolfboot_flash_locked = 1;
}

WP11_API void wolfboot_store_test_cleanup(void)
{
    if (wolfboot_store_region != NULL) {
        wolfboot_store_flush();
        if (wolfboot_store_mapped)
            munmap(wolfboot_store_region, wolfboot_store_region_sz);
        else
            free(wolfboot_store_region);
        wolfboot_store_region = NULL;
    }
    vault_base = NULL;
    wolfboot_store_region_sz = 0;
    wolfboot_flash_locked = 1;
}

static void __attribute__((constructor)) wolfboot_store_ctor(void)
{
    if (wolfboot_store_region == NULL)
        (void)wolfboot_store_test_init(NULL);
}

static void __attribute__((destructor)) wolfboot_store_dtor(void)
{
    if (wolfboot_store_region != NULL)
        wolfboot_store_test_cleanup();
}
