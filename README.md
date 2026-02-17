# wolfPKCS11

PKCS#11 library that implements cryptographic algorithms using wolfSSL.


## Project Features

## Building

Build wolfSSL:

```sh
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-aescfb --enable-rsapss --enable-keygen --enable-pwdbased --enable-scrypt C_EXTRA_FLAGS="-DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT -DHAVE_AES_ECB -DHAVE_AES_KEYWRAP"
make
make check
sudo make install
sudo ldconfig
```

autogen.sh requires: automake and libtool: `sudo apt-get install automake libtool`

Build wolfPKCS11:

```sh
git clone https://github.com/wolfSSL/wolfPKCS11.git
cd wolfPKCS11
./autogen.sh
./configure
make
make check
```
### TPM support with wolfTPM

Enables using a TPM for cryptography and keystore.
Tested using `./configure --enable-singlethreaded --enable-wolftpm --disable-dh CFLAGS="-DWOLFPKCS11_TPM_STORE" && make`.

Note: The TPM does not support DH, so only RSA and ECC are supported.

### Optional: AES-CCM Support

To have AES-CCM support in wolfPKCS11, configure both wolfSSL and wolfPKCS11
with the addition of `--enable-aesccm`.

### Optional: AES-ECB Support

To have AES-ECB support in wolfPKCS11, configure wolfSSL with the C macro
`HAVE_AES_ECB` defined. For example, `CFLAGS="-DHAVE_AES_ECB"`. Then
enable it in wolfPKCS11 with the addition of `--enable-aesecb` during the
configure step.

WARNING: ECB (Electronic Code Book) mode AES is generally considered to be
insecure. Please consider using a different mode of AES.

### Build options and defines

#### Define WOLFPKCS11_TPM_STORE

Use `WOLFPKCS11_TPM_STORE` storing objects in TPM NV.

#### Define WOLFPKCS11_NO_STORE

Disables storage of tokens.

#### Define WOLFPKCS11_DEBUG_STORE

Enables debugging printf's for store.

#### Define WOLFPKCS11_CUSTOM_STORE

Removes default implementation of storage functions.
See wolfpkcs11/store.h for prototypes of functions to implement.

#### Define WOLFPKCS11_KEYPAIR_GEN_COMMON_LABEL

Sets the private key's label against the public key when generating key pairs.

#### Analog Devices, Inc. MAXQ10xx Secure Elements ([MAXQ1065](https://www.analog.com/en/products/maxq1065.html)/MAXQ1080)

Support has been added to use the MAXQ10xx hardware for cryptographic operations
and storage of certificate.


Before usage:
1. Make sure the maxq10xx-sdk is installed and it has installed the proper
   header files into the source code for wolfPKCS11.
2. Edit `examples/maxq10xx_init.sh` to ensure it is pointing to the correct
   location.
3. Execute `examples/maxq10xx_init.sh` to ensure it is properly initialized.

NOTE: In the code, we have embedded a test key. This must be changed for
      production environments!! Please contact Analog Devices to learn how to
      obtain and use a production key.

## Building with CMake

wolfPKCS11 uses out-of-source builds. It also requires CMake 3.16 or later (3.22+ recommended).

### Building wolfSSL with CMake

wolfPKCS11 depends on wolfSSL. Build and install wolfSSL with CMake first:

```sh
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DWOLFSSL_AES=yes -DWOLFSSL_AESCBC=yes -DWOLFSSL_AESCCM=yes \
    -DWOLFSSL_AESCFB=yes -DWOLFSSL_AESECB=yes -DWOLFSSL_AESCTR=yes \
    -DWOLFSSL_AESGCM=yes -DWOLFSSL_AESKEYWRAP=yes -DWOLFSSL_AESOFB=yes \
    -DWOLFSSL_AESCTS=yes -DWOLFSSL_DH=yes -DWOLFSSL_DH_DEFAULT_PARAMS=yes \
    -DWOLFSSL_ECC=yes -DWOLFSSL_HKDF=yes -DWOLFSSL_KEYGEN=yes \
    -DWOLFSSL_MD5=yes -DWOLFSSL_RSA=yes -DWOLFSSL_RSA_PSS=yes \
    -DWOLFSSL_SHA=yes -DWOLFSSL_SHA224=yes -DWOLFSSL_SHA3=yes \
    -DWOLFSSL_SHA384=yes -DWOLFSSL_SHA512=yes \
    -DWOLFSSL_SP_MATH_ALL=yes -DWOLFSSL_PUBLIC_MP=yes \
    -DWOLFSSL_WC_RSA_DIRECT=yes -DCMAKE_BUILD_TYPE=Release \
    ..
cmake --build .
sudo cmake --install .
```

To install to a non-system directory instead, set
`-DCMAKE_INSTALL_PREFIX=<path>` and pass the same path as
`-DCMAKE_PREFIX_PATH=<path>` when building wolfPKCS11 below.

### Building wolfPKCS11 with CMake

```sh
cd wolfPKCS11
mkdir build && cd build
cmake ..
cmake --build .
ctest
```

To enable additional features, pass options during the configure step:

```sh
cmake -DWOLFPKCS11_DEBUG=yes \
    -DWOLFPKCS11_AESKEYWRAP=yes \
    -DWOLFPKCS11_AESCTR=yes \
    -DWOLFPKCS11_AESCCM=yes \
    -DWOLFPKCS11_AESECB=yes \
    -DWOLFPKCS11_AESCTS=yes \
    -DWOLFPKCS11_AESCMAC=yes \
    -DWOLFPKCS11_PBKDF2=yes \
    ..
cmake --build .
ctest
```

If wolfSSL was installed to a non-system prefix, point CMake to it:

```sh
cmake -DCMAKE_PREFIX_PATH=/path/to/wolfssl/install ..
```

### CMake Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `WOLFPKCS11_DEBUG` | `no` | Enable debug logging |
| `WOLFPKCS11_SINGLE_THREADED` | `no` | Single-threaded mode |
| `WOLFPKCS11_RSA` | `yes` | RSA support |
| `WOLFPKCS11_OAEP` | `yes` | RSA OAEP support |
| `WOLFPKCS11_RSA_PSS` | `yes` | RSA-PSS support |
| `WOLFPKCS11_KEYGEN` | `yes` | Key generation support |
| `WOLFPKCS11_ECC` | `yes` | ECC support |
| `WOLFPKCS11_DH` | `yes` | DH support |
| `WOLFPKCS11_AES` | `yes` | AES support |
| `WOLFPKCS11_AESCBC` | `yes` | AES-CBC support |
| `WOLFPKCS11_AESGCM` | `yes` | AES-GCM support |
| `WOLFPKCS11_AESKEYWRAP` | `no` | AES Key Wrap support |
| `WOLFPKCS11_AESCTR` | `no` | AES-CTR support |
| `WOLFPKCS11_AESCCM` | `no` | AES-CCM support |
| `WOLFPKCS11_AESECB` | `no` | AES-ECB support |
| `WOLFPKCS11_AESCTS` | `no` | AES-CTS support |
| `WOLFPKCS11_AESCMAC` | `no` | AES-CMAC support |
| `WOLFPKCS11_HMAC` | `yes` | HMAC support |
| `WOLFPKCS11_HKDF` | `yes` | HKDF support |
| `WOLFPKCS11_PBKDF2` | `no` | PBKDF2 for PIN hashing |
| `PBKDF2_ITERATIONS` | `600000` | PBKDF2 iteration count (used when `WOLFPKCS11_PBKDF2=yes`) |
| `WOLFPKCS11_MD5` | `yes` | MD5 support |
| `WOLFPKCS11_SHA1` | `yes` | SHA-1 support |
| `WOLFPKCS11_SHA224` | `yes` | SHA-224 support |
| `WOLFPKCS11_SHA256` | `yes` | SHA-256 support |
| `WOLFPKCS11_SHA384` | `yes` | SHA-384 support |
| `WOLFPKCS11_SHA512` | `yes` | SHA-512 support |
| `WOLFPKCS11_SHA3` | `yes` | SHA-3 support |
| `WOLFPKCS11_TPM` | `no` | wolfTPM keystore support |
| `WOLFPKCS11_NSS` | `no` | NSS-specific modifications |
| `WOLFPKCS11_PKCS11_V3_0` | `yes` | PKCS#11 v3.0 support |
| `WOLFPKCS11_PKCS11_V3_2` | `no` | PKCS#11 v3.2 support |
| `WOLFPKCS11_EXAMPLES` | `yes` | Build examples |
| `WOLFPKCS11_TESTS` | `yes` | Build and register tests |
| `WOLFPKCS11_COVERAGE` | `no` | Code coverage support |
| `WOLFPKCS11_INSTALL` | `yes` | Create install targets |
| `WOLFPKCS11_DEFAULT_TOKEN_PATH` | `""` | Default token storage path compiled into library |
| `WOLFPKCS11_BUILD_OUT_OF_TREE` | `yes` | Generate build artifacts outside source tree |
| `BUILD_SHARED_LIBS` | `ON` | Build shared (`ON`) or static (`OFF`) library |

Note: wolfSSL must be built with the corresponding features enabled for the
options above to work (e.g. enabling `WOLFPKCS11_AESCCM` requires wolfSSL built
with `-DWOLFSSL_AESCCM=yes`).

## Environment variables

### WOLFPKCS11_TOKEN_PATH

Path into which files are stored that contain token data. If unset, wolfPKCS11
tries, in order, the directory specified by `WOLFPKCS11_TOKEN_PATH`, any store
directory configured by NSS, the user's home directory (`~/.wolfPKCS11` on
POSIX or `%APPDIR%\wolfPKCS11` on Windows), and finally the optional
`WOLFPKCS11_DEFAULT_TOKEN_PATH` build-time setting. There is no fallback to
`/tmp`; deployments must provide a secure storage location explicitly.

### WOLFPKCS11_NO_STORE

Set to any value to stop storage of token data.


## Release Notes

### wolfPKCS11 Release 2.0 (August 26, 2025)

**Summary**

This release contains many new features so that it can be the PKCS11 backend for NSS. It also includes many bug fixes.

**Detail**

* New examples added
* Added certificate storage for wolfPKCS11
* Added new AES algorithms:
  - `AES-CCM`
  - `AES-ECB`
  - `AES-CTS`
  - `AES-CTR`
* Compiler fixes
* Large improvements to TPM storage
* Reduced memory usage for objects
* Added support for MAXQ1065
* Fixed RSA with no public exponent provided
* Fixed `CKA_CERTIFICATE_TYPE` search for `CKC_X_509`
* Fixed RSA with no modulus provided
* Fixed bad memory access with `C_FindObjects` on a certificate object
* Added new functionality:
  - `C_Digest*`
  - `C_SignEncryptUpdate`
  - `C_DecryptVerifyUpdate`
  - `C_GetOperationState` and `C_SetOperationState` (Digest only)
  - `C_SignRecoverInit` and `C_VerifyRecover`
  - `wolfPKCS11_Debugging_On` and `wolfPKCS11_Debugging_Off`
* Added new mechanisms:
  - `CKM_ECDSA_SHA*`
  - `CKM_SHA*_RSA*`
  - `CKM_AES_CMAC_GENERAL`
  - `CKM_AES_CMAC`
  - `CKM_AES_CBC_ENCRYPT_DATA`
  - `CKM_HKDF_DATA`
  - `CKM_HKDF_KEY_GEN`
  - `CKM_TLS12_KEY_AND_MAC_DERIVE`
  - `CKM_TLS12_MASTER_KEY_DERIVE`
  - `CKM_TLS12_MASTER_KEY_DERIVE_DH`
  - `CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE` (NSS builds only)
  - `CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH` (NSS builds only)
  - `CKM_NSS_TLS_PRF_GENERAL_SHA256` (NSS builds only)
  - `CKM_TLS_MAC`
  - `CKM_SHA1_RSA_PKCS`
  - `CKM_SHA1_RSA_PKCS_PSS`
  - `CKM_SHA3*`
  - `CKM_MD5`
  - `CKM_NSS_PKCS12_PBE_SHA*_HMAC_KEY_GEN` (NSS builds only)
  - `CKM_PKCS5_PBKD2`
* Added new types:
  - `CKO_DATA`
  - `CKO_NSS_TRUST` (NSS builds only)
* Added new attributes:
  - `CKA_CERTIFICATE_TYPE`
  - `CKA_CERTIFICATE_CATEGORY`
  - `CKA_ID`
  - `CKA_ISSUER`
  - `CKA_SERIAL_NUMBER`
  - `CKA_PUBLIC_KEY_INFO`
  - `CKA_URL`
  - `CKA_HASH_OF_SUBJECT_PUBLIC_KEY`
  - `CKA_HASH_OF_ISSUER_PUBLIC_KEY`
  - `CKA_NAME_HASH_ALGORITHM`
  - `CKA_CHECK_VALUE`
  - `CKA_CERT_SHA1_HASH` (NSS builds only)
  - `CKA_CERT_MD5_HASH` (NSS builds only)
  - `CKA_TRUST_SERVER_AUTH` (NSS builds only)
  - `CKA_TRUST_CLIENT_AUTH` (NSS builds only)
  - `CKA_TRUST_EMAIL_PROTECTION` (NSS builds only)
  - `CKA_TRUST_CODE_SIGNING` (NSS builds only)
  - `CKA_TRUST_STEP_UP_APPROVED` (NSS builds only)
  - `CKA_NSS_EMAIL` (NSS builds only)
  - `CKA_NSS_DB` (NSS builds only, not stored)
* Added SHA3 support for digest and HMAC
* Added AES key gen and key wrap
* Added `--enable-nss` for NSS specific PKCS11 quirks
* Fixed ECC derive key curve error
* Fixed object boolean attributes and permissions
* Fixed `C_SetAttributeValue` sometimes erasing keys
* Fixed wolfCrypt FIPSv5 and FIPSv6 support
* Fixed token erasure on load error
* Fixed various memory leaks
* Complete re-write of file based token path handling
* Added debugging output
* Fixed visibility issues
* Fixed x963 usage for ECC keys
* Added support for older wolfSSL versions
* Fixed token overwriting previous objects
* Fixed token load error handling
* Improved error handling for `C_Login`
* Improved Debian packaging
* Fixed build issues with wolfBoot
* Fixed `malloc(0)` code path
* Fixed `C_CopyObject` not doing a deep copy
* Added `CKM_RSA_PKCS` to wrap / unwrap
* Fixed ECC curve lookup for FIPSv5
* Fixed default attributes for keys
* `C_DestroyObject` now deletes files instead of leaving truncated files
* Added support for STM32U5 DHUK wrapping
* Added PBKDF2 support for pins
  - Enabled by default for FIPS
  - Enabled using `--enable-pbkdf2` or defining `WOLFPKCS11_PBKDF2`
* Added `--pbkdf2-iterations` and `PBKDF2_ITERATIONS` to set the number of
  PBKDF2 iterations for pin handling (default 600,000).

### wolfPKCS11 Release 1.3 (Mar 22, 2024)

**Summary**

Added Visual Studio support for wolfPKCS11. Fixes for cast warnings and portability.

**Detail**

* Fixed `C_GetAttributeValue` incorrectly erroring with `CKR_ATTRIBUTE_VALUE_INVALID` when data == NULL. The `C_GetAttributeValue` should set length if data field is NULL. (PR #27)
* Fixed several cast warnings and possible use of uninitialized. (PR #28)
* Fixed portability issues with `WOLFPKCS11_USER_SETTINGS`. (PR #28)
* Added Visual Studio support for wolfPKCS11. (PR #28)
  - This includes wolfTPM support with Windows TBS interface
* Reworked shared library versioning. (PR #29)


### wolfPKCS11 Release 1.2 (Dec 26, 2023)

**Summary**

Adds backend support for TPM 2.0 using wolfTPM. Adds AES CBC key wrap / unwrap support. Portability improvements. Improved testing with GitHub Actions.

**Detail**

* Cleanups for minor cast warning, spelling and ignore for generated test files (PR #14)
* Added support for wrap/unwrap RSA with aes_cbc_pad. (PR #15)
* Fixed setting of label for public key after creation (init ECC objects before decoding) (PR #16)
* Flush writes in key store. (PR #17)
* Added build options for embedded use (PR #18)
  - `WOLFSSL_USER_SETTINGS` to avoid including `wolfssl/options.h`
  - `WOLFPKCS11_USER_SETTINGS` to avoid including `wolfPKCS11/options.h`
  - `WOLFPKCS11_NO_TIME` to make wc_GetTime() optional (it disables brute-force protections on token login)
* Reset failed login counter only with `WOLFPKCS11_NO_TIME` (PR #18)
* Fixed argument passing in `SetMPI`/`GetMPIData` (PR #19)
* Fixed `NO_DH` ifdef gate when freeing PKCS11 object (PR #20)
* Added GitHub CI action (PR #21)
* Fixed warnings from `./autogen.sh`. Updated m4 macros. (PR #21)
* Added additional GitHub CI action tests. (PR #22)
* Added wolfPKCS11 support for using TPM 2.0 module as backend. Uses wolfTPM and supports RSA and ECC. Requires https://github.com/wolfSSL/wolfTPM/pull/311 (PR #23)
* Added CI testing for wolfPKCS11 with wolfTPM backend and single threaded. (PR #23)
* Added PKCS11 TPM NV store (enabled with `WOLFPKCS11_TPM_STORE`). Allow `WOLFPKCS11_NO_STORE` for TPM use case. (PR #23)
* Fixed compiler warnings from mingw. (PR #23)
* Added portability macro `WOLFPKCS11_NO_ENV` when setenv/getenv are not available. (PR #23)
* Fix to only require `-ldl` for non-static builds. (PR #23)
* Portability fixes. Added `NO_MAIN_DRIVER`. Support for `SINGLE_THREADED`. Add `static` to some globals. (PR #24)
* Fixes for portability where `XREALLOC` is not available. (PR #25)
* Added support for custom setenv/get env using `WOLFPKCS11_USER_ENV`. (PR #25)
* Fix for final not being called after init in edge case pin failure. (PR #25)
* Added support for hashing PIN with SHA2-256.
  - PKS11 uses scrypt, which uses multiple MB of memory and is not practical for embedded systems. (PR #25)

### wolfPKCS11 Release 1.1 (May 6, 2022)

* Added support for CKM_AES_CBC_PAD
* Added support for storage of token data.
* Added support encrypted private keys.
* Added CKF_LOGIN_REQUIRED to the slot flags.
* Added RSA X_509 support for signing/verifying
* Added missing `CK_INVALID_SESSION`.
* Added some missing PKCS11 types.
* Fixed building with FIPS 140-2 (fipsv2).
* Fixed `WP11_API` visibility.
* Fixed test pin to be at least 14-characters as required by FIPS HMAC.
* Fixed getting a boolean for the operations flags.
* Fixed misleading indentation fixes.
* Improve the `curve_oid` lookup with FIPS.
* Removed `config.h` from the public pkcs11.h header.
* Convert repository to GPLv3.

### wolfPKCS11 Release 1.0 (October 20, 2021)

* Initial PKCS11 support
