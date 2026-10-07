/* info_mech_table_test.c
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
 * Library, slot, token and mechanism information must match the PKCS#11
 * encoding rules and what the token actually implements.
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

#define TEST_DIR "./store/info_mech_table_test"

/* Fixed-length character fields are blank padded and never contain NUL. */
static int blank_padded(const CK_UTF8CHAR* field, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (field[i] == '\0')
            return 0;
    }
    return 1;
}

static void check_info(CK_FUNCTION_LIST* list, const char* name)
{
    CK_RV rv;
    CK_INFO info;
    char msg[96];

    XMEMSET(&info, 0, sizeof(info));
    rv = list->C_GetInfo(&info);
    snprintf(msg, sizeof(msg), "C_GetInfo(%s)", name);
    CHECK_RV(rv, msg, CKR_OK);
    if (rv != CKR_OK)
        return;
    snprintf(msg, sizeof(msg), "%s CK_INFO.manufacturerID blank padded", name);
    CHECK_TRUE(blank_padded(info.manufacturerID, sizeof(info.manufacturerID)),
               msg);
    snprintf(msg, sizeof(msg), "%s CK_INFO.libraryDescription blank padded",
             name);
    CHECK_TRUE(blank_padded(info.libraryDescription,
                            sizeof(info.libraryDescription)), msg);
}

static void test_info_blank_padding(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
#ifdef WOLFPKCS11_PKCS11_V3_0
    CK_INTERFACE interfaces[8];
    CK_ULONG count = sizeof(interfaces) / sizeof(interfaces[0]);
    CK_ULONG i;
    char name[32];
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetInterfaceList getList;
#endif
#endif

    check_info(funcList, "v2");

#ifdef WOLFPKCS11_PKCS11_V3_0
#ifndef HAVE_PKCS11_STATIC
    getList = (CK_C_GetInterfaceList)dlsym(dlib, "C_GetInterfaceList");
    CHECK_TRUE(getList != NULL, "C_GetInterfaceList symbol");
    rv = (getList != NULL) ? getList(interfaces, &count) : CKR_GENERAL_ERROR;
#else
    rv = C_GetInterfaceList(interfaces, &count);
#endif
    CHECK_RV(rv, "C_GetInterfaceList", CKR_OK);
    for (i = 0; rv == CKR_OK && i < count; i++) {
        snprintf(name, sizeof(name), "interface %lu", (unsigned long)i);
        check_info((CK_FUNCTION_LIST*)interfaces[i].pFunctionList, name);
    }
#endif

    XMEMSET(&slotInfo, 0, sizeof(slotInfo));
    rv = funcList->C_GetSlotInfo(slot, &slotInfo);
    CHECK_RV(rv, "C_GetSlotInfo", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(blank_padded(slotInfo.slotDescription,
                                sizeof(slotInfo.slotDescription)),
                   "CK_SLOT_INFO.slotDescription blank padded");
        CHECK_TRUE(blank_padded(slotInfo.manufacturerID,
                                sizeof(slotInfo.manufacturerID)),
                   "CK_SLOT_INFO.manufacturerID blank padded");
    }

    XMEMSET(&tokenInfo, 0, sizeof(tokenInfo));
    rv = funcList->C_GetTokenInfo(slot, &tokenInfo);
    CHECK_RV(rv, "C_GetTokenInfo", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(blank_padded(tokenInfo.label, sizeof(tokenInfo.label)),
                   "CK_TOKEN_INFO.label blank padded");
        CHECK_TRUE(blank_padded(tokenInfo.manufacturerID,
                                sizeof(tokenInfo.manufacturerID)),
                   "CK_TOKEN_INFO.manufacturerID blank padded");
        CHECK_TRUE(blank_padded(tokenInfo.model, sizeof(tokenInfo.model)),
                   "CK_TOKEN_INFO.model blank padded");
        CHECK_TRUE(blank_padded(tokenInfo.serialNumber,
                                sizeof(tokenInfo.serialNumber)),
                   "CK_TOKEN_INFO.serialNumber has no NUL bytes");
    }
}

static int two_digits(const CK_CHAR* p, int* val)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9')
        return 0;
    *val = (p[0] - '0') * 10 + (p[1] - '0');
    return 1;
}

/* A token that claims a clock must report a valid UTC time. */
static void test_token_clock(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_TOKEN_INFO tokenInfo;
    int century = 0, year = 0, month = 0, day = 0;
    int hour = 0, minute = 0, second = 0;
    int valid;

    XMEMSET(&tokenInfo, 0, sizeof(tokenInfo));
    rv = funcList->C_GetTokenInfo(slot, &tokenInfo);
    CHECK_RV(rv, "C_GetTokenInfo(clock)", CKR_OK);
    if (rv != CKR_OK)
        return;

    if ((tokenInfo.flags & CKF_CLOCK_ON_TOKEN) == 0) {
        CHECK_TRUE(XMEMCMP(tokenInfo.utcTime, "                ",
                           sizeof(tokenInfo.utcTime)) == 0,
                   "utcTime is blank without a clock");
        return;
    }

    valid = two_digits(&tokenInfo.utcTime[0], &century) &&
            two_digits(&tokenInfo.utcTime[2], &year) &&
            two_digits(&tokenInfo.utcTime[4], &month) &&
            two_digits(&tokenInfo.utcTime[6], &day) &&
            two_digits(&tokenInfo.utcTime[8], &hour) &&
            two_digits(&tokenInfo.utcTime[10], &minute) &&
            two_digits(&tokenInfo.utcTime[12], &second);
    CHECK_TRUE(valid && century * 100 + year >= 1970 &&
               month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
               hour <= 23 && minute <= 59 && second <= 60,
               "CKF_CLOCK_ON_TOKEN reports a valid utcTime");
}

static int run_test(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
        CHECK_RV(rv, "C_GetSlotList", CKR_OK);
    }
    if (rv == CKR_OK && slotCount == 0) {
        CHECK_TRUE(0, "at least one slot");
        rv = CKR_TOKEN_NOT_PRESENT;
    }
    if (rv == CKR_OK) {
        test_info_blank_padding(slotList[0]);
        test_token_clock(slotList[0]);
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

    printf("=== wolfPKCS11 info and mechanism table test ===\n");
    run_test();
    return pkcs11_test_summary();
}
