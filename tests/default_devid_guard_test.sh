#!/bin/sh
# Run from a configured tree built against wolfSSL with crypto callbacks.
# Checks the WOLFPKCS11_PIN_KDF_SOFTWARE and WOLFPKCS11_DEFAULT_DEVID guards.
mkvar() {
    printf 'print-var:\n\t@echo %s\n' "$1" | make -s -f Makefile -f - print-var
}
cc=$(mkvar '$(CC)')
flags=$(mkvar '$(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS)')
flags="$flags $(mkvar '$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)')"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
err="$tmp/err"

# Include overrides go before the build flags, macro changes after them
inc=
pp() {
    $cc $inc $flags "$@" -E src/internal.c -o /dev/null 2>"$err"
}

accept() {
    what=$1
    shift
    if ! pp "$@"; then
        echo "FAIL: $what was rejected"
        cat "$err"
        exit 1
    fi
}

reject() {
    what=$1
    msg=$2
    shift 2
    if pp "$@"; then
        echo "FAIL: $what was accepted"
        exit 1
    fi
    if ! grep -q "$msg" "$err"; then
        echo "FAIL: $what failed without the expected error: $msg"
        cat "$err"
        exit 1
    fi
}

version_header() {
    mkdir -p "$tmp/$1/wolfssl"
    {
        printf '#ifndef WOLFSSL_VERSION_H\n#define WOLFSSL_VERSION_H\n'
        printf '#define LIBWOLFSSL_VERSION_STRING "%s"\n' "$2"
        printf '#define LIBWOLFSSL_VERSION_HEX %s\n#endif\n' "$3"
    } > "$tmp/$1/wolfssl/version.h"
}

version_header old 5.7.2 0x05007002
version_header min 5.7.4 0x05007004
inc="-I$tmp/min"
accept "PIN KDF with wolfSSL 5.7.4" -DWOLFPKCS11_PIN_KDF_SOFTWARE
reject "PIN KDF with WOLF_CRYPTO_CB_FIND" \
    "conflicts with WOLF_CRYPTO_CB_FIND" \
    -DWOLFPKCS11_PIN_KDF_SOFTWARE -DWOLF_CRYPTO_CB_FIND
inc="-I$tmp/old"
accept "preprocessing with the 5.7.2 version header"
reject "PIN KDF with wolfSSL 5.7.2" "requires wolfSSL 5.7.4 or later" \
    -DWOLFPKCS11_PIN_KDF_SOFTWARE

mkdir -p "$tmp/nopb/wolfpkcs11"
grep -v WOLFPKCS11_PBKDF2 wolfpkcs11/options.h \
    > "$tmp/nopb/wolfpkcs11/options.h"
inc="-I$tmp/nopb -I$tmp/old"
accept "PIN KDF without PBKDF2" -UWOLFPKCS11_PBKDF2 \
    -DWOLFPKCS11_PIN_KDF_SOFTWARE

inc=
accept "default device ID" -DWOLFPKCS11_DEFAULT_DEVID=7
# Empty stand-ins for vendor headers a host build lacks; -E needs no types
for h in wolfssl/wolfcrypt/port/st/stm32.h \
        wolfssl/wolfcrypt/port/maxim/maxq10xx.h \
        wolfpkcs11/port/maxim/MXQ_API.h; do
    mkdir -p "$tmp/vendor/$(dirname "$h")"
    : > "$tmp/vendor/$h"
done
inc="-I$tmp/vendor"
reject "default device ID with STM32U5 DHUK" "conflicts with a TPM" \
    -DWOLFPKCS11_DEFAULT_DEVID=7 -DWOLFSSL_STM32U5_DHUK
reject "default device ID with MAXQ10XX" "conflicts with a TPM" \
    -DWOLFPKCS11_DEFAULT_DEVID=7 -DWOLFSSL_MAXQ10XX_CRYPTO
inc=
if printf '#include <wolftpm/tpm2_wrap.h>\n' |
        $cc $flags -E -x c - -o /dev/null 2>/dev/null; then
    reject "default device ID with the TPM backend" "conflicts with a TPM" \
        -DWOLFPKCS11_DEFAULT_DEVID=7 -DWOLFPKCS11_TPM
else
    echo "SKIP: wolfTPM headers not found, TPM guard case not run"
fi
echo "PASS: PIN KDF and default device ID configuration guards"
