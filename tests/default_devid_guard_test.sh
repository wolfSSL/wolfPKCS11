#!/bin/sh
# Run from a configured tree built against wolfSSL with crypto callbacks.
# WOLFPKCS11_PIN_KDF_SOFTWARE must reject builds where PBKDF2 can reach a device.
flags=$(printf 'print-flags:\n\t@echo $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)\n' |
    make -s -f Makefile -f - print-flags)

pp() {
    ${flags%% *} "$@" ${flags#* } -E src/internal.c -o /dev/null 2>/dev/null
}

if ! pp -DWOLFPKCS11_PIN_KDF_SOFTWARE -DWC_NO_DEFAULT_DEVID; then
    echo "FAIL: valid PIN KDF configuration was rejected"
    exit 1
fi
if pp -DWOLFPKCS11_PIN_KDF_SOFTWARE; then
    echo "FAIL: PIN KDF without WC_NO_DEFAULT_DEVID was accepted"
    exit 1
fi
if pp -DWOLFPKCS11_PIN_KDF_SOFTWARE -DWC_NO_DEFAULT_DEVID -DWOLF_CRYPTO_CB_FIND; then
    echo "FAIL: PIN KDF with WOLF_CRYPTO_CB_FIND was accepted"
    exit 1
fi
nopb=$(mktemp -d)
mkdir -p "$nopb/wolfpkcs11"
grep -v WOLFPKCS11_PBKDF2 wolfpkcs11/options.h > "$nopb/wolfpkcs11/options.h"
if ! ${flags%% *} -I"$nopb" ${flags#* } -UWOLFPKCS11_PBKDF2 \
        -DWOLFPKCS11_PIN_KDF_SOFTWARE -E src/internal.c -o /dev/null 2>/dev/null; then
    rm -rf "$nopb"
    echo "FAIL: PIN KDF without PBKDF2 was rejected"
    exit 1
fi
rm -rf "$nopb"
old=$(mktemp -d)
mkdir -p "$old/wolfssl"
printf '#ifndef WOLFSSL_VERSION_H\n#define WOLFSSL_VERSION_H\n#define LIBWOLFSSL_VERSION_STRING "5.6.6"\n#define LIBWOLFSSL_VERSION_HEX 0x05006006\n#endif\n' \
    > "$old/wolfssl/version.h"
if ! pp -I"$old" -DWC_NO_DEFAULT_DEVID; then
    rm -rf "$old"
    echo "FAIL: preprocessing with the old wolfSSL version header failed"
    exit 1
fi
if pp -I"$old" -DWOLFPKCS11_PIN_KDF_SOFTWARE -DWC_NO_DEFAULT_DEVID; then
    rm -rf "$old"
    echo "FAIL: PIN KDF with wolfSSL older than 5.8.0 was accepted"
    exit 1
fi
rm -rf "$old"
echo "PASS: PIN KDF configuration guards"
