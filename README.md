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

### Optional: PQC ML-DSA Support

To have ML-DSA support in wolfPKCS11, configure wolfSSL with ML-DSA support
enabled, either by adding `--enable-mldsa` to `./configure` or by setting
`WOLFSSL_MLDSA` to `yes` in CMake. wolfPKCS11 uses the canonical
`wc_MlDsaKey` API and `WC_MLDSA_*` sizing macros (FIPS 204 spelling) and
therefore requires a wolfSSL build that incorporate these.

As ML-DSA is a feature of PKCS#11 version 3.2, support for that is required,
too. Hence, to enable all in wolfPKCS11, add `--enable-pkcs11v32 --enable-mldsa`
during the configure step.

### Optional: PQC ML-KEM Support

To have ML-KEM support in wolfPKCS11, configure wolfSSL with ML-KEM (FIPS 203)
support enabled, either by adding `--enable-mlkem` to `./configure` or by
setting `WOLFPKCS11_MLKEM` to `yes` in CMake.

As ML-KEM is a feature of PKCS#11 version 3.2, support for that is required,
too. Hence, to enable all in wolfPKCS11, add `--enable-pkcs11v32 --enable-mlkem`
during the configure step.

### Optional: Self-contained library with static wolfSSL

By default libwolfpkcs11 loads libwolfssl at run time. To ship a single
library instead, build wolfSSL as a static library with position independent
code and link it into libwolfpkcs11:

```sh
cd wolfssl
./configure --enable-static --disable-shared --with-pic --enable-cryptonly \
    --enable-aescfb --enable-rsapss --enable-keygen --enable-pwdbased \
    --enable-scrypt \
    C_EXTRA_FLAGS="-DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT -DHAVE_AES_ECB -DHAVE_AES_KEYWRAP"
make
sudo make install

cd ../wolfPKCS11
./configure --with-static-wolfssl=/usr/local/lib/libwolfssl.a
make
```

The wolfSSL symbols stay hidden inside libwolfpkcs11, so an application using
its own wolfSSL, even with a different configuration, can load the module with
`dlopen()` or `wc_Pkcs11_Initialize()`. Settings the application makes on its
own wolfSSL, such as `wolfSSL_SetAllocators()`, do not reach the module. A
wolfSSL update requires rebuilding libwolfpkcs11. This option needs an ELF
linker (GNU ld, gold or lld) and cannot be combined with wolfTPM support. If
the static wolfSSL needs other libraries, such as zlib, pass them in `LIBS`:
the ones `pkg-config --static --libs wolfssl` lists after `-lwolfssl`.

With CMake, build wolfSSL with `-DBUILD_SHARED_LIBS=OFF` and
`-DCMAKE_POSITION_INDEPENDENT_CODE=ON`, then configure wolfPKCS11 with
`-DWOLFPKCS11_STATIC_WOLFSSL=yes`.

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

#### Define WOLFPKCS11_LEGACY_COPYABLE_FALSE_DEFAULT

Restores the pre-fix behavior where `C_GetAttributeValue(CKA_COPYABLE)` always
reports `CK_FALSE`, regardless of whether the attribute was explicitly set.
The default (without this flag) reports `CK_TRUE` for new objects and reflects
the stored value for objects whose `CKA_COPYABLE` was explicitly set, matching
the PKCS#11 specification. Define this only if your application or stored
tokens depend on the old read-back behavior. The `C_CopyObject` enforcement
consults the stored copyable flag directly via `WP11_Object_IsCopyable`, so
this macro does not change which objects can be copied; objects created with
`CKA_COPYABLE=CK_TRUE` (the default) remain copyable, and objects created
with `CKA_COPYABLE=CK_FALSE` are still rejected by `C_CopyObject` with
`CKR_ACTION_PROHIBITED`.

### Behavior changes for PKCS#11 spec compliance

Several pre-existing gaps were closed; applications upgrading from earlier
versions may need to update templates or error-handling:

- `C_DeriveKey` now enforces `CKA_DERIVE` on the base key. Keys that do not
  set `CKA_DERIVE=CK_TRUE` at creation are rejected with
  `CKR_KEY_TYPE_INCONSISTENT`. RSA, EC, and ML-DSA private keys default
  `CKA_DERIVE` to `CK_FALSE`, so applications doing ECDH or other key
  derivation must now set `CKA_DERIVE=CK_TRUE` explicitly in the key
  template. The check is skipped on `--enable-nss` builds because NSS
  generates ephemeral ECDHE keys without setting `CKA_DERIVE` and relies on
  the historic permissive behavior; non-NSS builds get the spec-compliant
  enforcement.
- `C_CopyObject` enforces `CKA_COPYABLE` (returns `CKR_ACTION_PROHIBITED`
  on `CK_FALSE`).
- `C_DestroyObject` enforces `CKA_DESTROYABLE` (returns
  `CKR_ACTION_PROHIBITED` on `CK_FALSE`).
- `C_EncapsulateKey`/`C_DecapsulateKey` enforce `CKA_ENCAPSULATE` /
  `CKA_DECAPSULATE` and return `CKR_KEY_FUNCTION_NOT_PERMITTED` when the
  flag is `CK_FALSE`.
- `C_SetAttributeValue` rejects flipping `CKA_COPYABLE` or
  `CKA_DESTROYABLE` from `CK_FALSE` back to `CK_TRUE`, returning
  `CKR_ATTRIBUTE_READ_ONLY` per spec section 4.4.1.
- `C_Login(CKU_SO, ...)` against a token whose SO PIN has not been set
  now returns `CKR_USER_PIN_NOT_INITIALIZED` regardless of the PIN
  length, closing an empty-PIN bypass where the zero-length constant
  compare against the unset stored PIN returned equal. NSS builds
  (`--enable-nss`) keep the empty-PIN probe accepted on uninitialized
  tokens because `PK11_InitPin` bootstraps an empty-password NSS
  database that way; non-empty PINs are still rejected.
- On `--enable-nss` builds `WP11_MIN_PIN_LEN` defaults to `0`, permitting a
  zero-length user PIN. An empty user PIN intentionally disables PIN-based
  authentication: `C_GetTokenInfo` clears `CKF_LOGIN_REQUIRED` and all
  private/token objects are decoded and accessible at token load without
  `C_Login`. This is required for NSS tools (`certutil`, `PK11_InitPin`) that
  bootstrap empty-password databases. Integrators who require an enforced
  minimum can opt in at build time with `C_EXTRA_FLAGS="-DWP11_MIN_PIN_LEN=N"`
  (`N>0`); non-NSS builds already default to `4`.
- `C_GetAttributeValue` returns `CKR_ATTRIBUTE_TYPE_INVALID` when a template
  names an attribute the object does not have or that is not supported, and
  keeps processing the rest of the template. Previously such attributes
  returned `CK_UNAVAILABLE_INFORMATION` as the function's return value, and
  `CKA_CERTIFICATE_TYPE` on a non-certificate object failed the whole call
  with `CKR_FUNCTION_FAILED`. In both cases the attribute's `ulValueLen` is
  set to `CK_UNAVAILABLE_INFORMATION`.
- `CKA_KEY_TYPE` is only an attribute of key objects. Reading it from a
  certificate or data object now returns `CKR_ATTRIBUTE_TYPE_INVALID` (an
  X.509 certificate previously read back as `CKK_RSA`), `C_FindObjects` with
  `CKA_KEY_TYPE` in the template no longer matches non-key objects, and
  `C_SetAttributeValue` of `CKA_KEY_TYPE` on them returns
  `CKR_ATTRIBUTE_TYPE_INVALID`.

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
    -DWOLFSSL_WC_RSA_DIRECT=yes -DWOLFSSL_DILITHIUM=yes \
    -DCMAKE_BUILD_TYPE=Release \
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
    -DWOLFPKCS11_PKCS11_V3_2=yes \
    -DWOLFPKCS11_MLDSA=yes \
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
| `WOLFPKCS11_MLDSA` | `no` | ML-DSA support |
| `WOLFPKCS11_MLKEM` | `no` | ML-KEM support |
| `WOLFPKCS11_EXAMPLES` | `yes` | Build examples |
| `WOLFPKCS11_TESTS` | `yes` | Build and register tests |
| `WOLFPKCS11_COVERAGE` | `no` | Code coverage support |
| `WOLFPKCS11_INSTALL` | `yes` | Create install targets |
| `WOLFPKCS11_DEFAULT_TOKEN_PATH` | `""` | Default token storage path compiled into library |
| `WOLFPKCS11_BUILD_OUT_OF_TREE` | `yes` | Generate build artifacts outside source tree |
| `BUILD_SHARED_LIBS` | `ON` | Build shared (`ON`) or static (`OFF`) library |
| `WOLFPKCS11_STATIC_WOLFSSL` | `no` | Link a static wolfSSL into the shared library and hide its symbols |

Note: wolfSSL must be built with the corresponding features enabled for the
options above to work (e.g. enabling `WOLFPKCS11_AESCCM` requires wolfSSL built
with `-DWOLFSSL_AESCCM=yes`).

## Environment variables

### WOLFPKCS11_TOKEN_PATH

Path into which files are stored that contain token data. wolfPKCS11 uses the
first of the following that is set:

1. The `WOLFPKCS11_TOKEN_PATH` environment variable.
2. Any store directory configured by NSS.
3. The `WOLFPKCS11_DEFAULT_TOKEN_PATH` build-time setting.
4. The user's home directory (`$HOME/.wolfPKCS11` on POSIX or
   `%APPDATA%\wolfPKCS11` on Windows).

There is no fallback to `/tmp`; deployments must provide a secure storage
location explicitly.

`WOLFPKCS11_DEFAULT_TOKEN_PATH` is set with `--with-default-token-path=PATH`
(autotools) or `-DWOLFPKCS11_DEFAULT_TOKEN_PATH=PATH` (CMake). When defining it
directly, for example in `user_settings.h`, it must be a C string literal such
as `#define WOLFPKCS11_DEFAULT_TOKEN_PATH "/var/lib/wolfpkcs11"`. Backslashes
are escape characters in a C string, so use forward slashes in Windows paths.

Note: releases 2.0 and 2.1 checked the home directory before
`WOLFPKCS11_DEFAULT_TOKEN_PATH`, so the build-time default was only used when
`HOME` was unset. Those releases also compiled the path set by
`--with-default-token-path` or the CMake option in with literal quote
characters around it, so the configured directory was never used. POSIX
deployments built with a default path that have existing tokens in
`$HOME/.wolfPKCS11` should set `WOLFPKCS11_TOKEN_PATH` to that directory, or
move the token files into the build-time default directory. Builds that passed
an unquoted value directly, for example
`CFLAGS="-DWOLFPKCS11_DEFAULT_TOKEN_PATH=/some/path"`, no longer compile; use
`--with-default-token-path` instead.

Releases 2.0 and 2.1 also looked up a non-existent `APPDIR` variable on
Windows, so no per-user default was used there and token data went to
`WOLFPKCS11_DEFAULT_TOKEN_PATH` (or token storage failed if it was unset).
Windows builds now fall back to `%APPDATA%\wolfPKCS11` when no build-time
default is set.

### WOLFPKCS11_NO_STORE

Set to any value to stop storage of token data.


## Release Notes

### wolfPKCS11 Release 2.2 (Oct 21, 2026)

**Summary**

This release adds verify-only LMS/HSS and XMSS/XMSS^MT support, an option to
link a static wolfSSL into libwolfpkcs11, and partial token writes that make
creating and destroying token objects much faster on custom stores. It also
fixes a large number of PKCS#11 specification compliance, memory-safety and
concurrency issues found through static analysis and external reports, fixes
TPM ECDH, the Windows ABI and the default token path, and enables
ThreadSanitizer in CI.

**Compatibility with 2.1 behavior**

Some of these fixes change behavior that applications or stored tokens may
depend on:

* Key material in stored token objects is now encrypted with the object's
  policy (class, key type, key generation mechanism, local flag and operation
  flags) as authenticated data. Tokens written by 2.1 and earlier still load,
  and each object is rewritten in the new format the next time it is stored.
  Earlier releases cannot read objects in the new format, so a token used with
  2.2 cannot be moved back to an earlier release. (PR #243)
* The token path lookup order is now `WOLFPKCS11_TOKEN_PATH`, the NSS store
  directory, `WOLFPKCS11_DEFAULT_TOKEN_PATH`, then the home directory, and a
  path set with `--with-default-token-path` is now used. POSIX builds that set
  a default path and have tokens in `$HOME/.wolfPKCS11` need to set
  `WOLFPKCS11_TOKEN_PATH` or move the token files. See the
  `WOLFPKCS11_TOKEN_PATH` section above. (PR #225, PR #247)
* On Windows the PKCS#11 structures now use 1-byte packing, the layout other
  PKCS#11 modules and applications use there. Applications must be rebuilt
  with the new headers. Define `WOLFPKCS11_NO_PACKED_STRUCTS` to keep the
  previous layout. (PR #209)
* `CKM_AES_CMAC` now produces and checks a full 16-byte MAC. Earlier releases
  used 8 bytes. (PR #243)
* `CKA_CHECK_VALUE` of a generic secret key is now the first three bytes of
  the SHA-1 hash of its value, as PKCS#11 3.2 defines. AES-192 keys and
  generic secrets that are not an AES key length now return a check value
  instead of failing with `CKR_FUNCTION_FAILED`. (PR #248)
* `C_GetAttributeValue` returns `CKR_ATTRIBUTE_TYPE_INVALID` for attributes an
  object does not have and keeps processing the template, and `CKA_KEY_TYPE`
  is only an attribute of key objects. (PR #222)
* Templates are checked more strictly. `C_SetAttributeValue` rejects changes to
  `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_MODIFIABLE`, key components and certificate
  values. `C_CreateObject` requires the key or certificate value.
  `C_GenerateKey` and `C_GenerateKeyPair` reject a class or key type that does
  not match the mechanism. Setting `CKA_ALWAYS_AUTHENTICATE` to `CK_TRUE`
  returns `CKR_ATTRIBUTE_VALUE_INVALID`. (PR #216, PR #243)
* In non-NSS builds, finding, using or creating private objects needs a normal
  user login, so an SO session can no longer use them. `C_DeriveKey`,
  `C_EncapsulateKey` and `C_DecapsulateKey` need a user login when the new key
  is private. Closing all sessions now logs the application out, and setting
  `CKA_TRUSTED` needs an SO session. (PR #207, PR #212, PR #227, PR #243)
* EC keys generated on a TPM slot are now created with TPM capabilities that
  match `CKA_SIGN` and `CKA_DERIVE`, and ECDH runs on the TPM. TPM EC keys
  stored by earlier releases were created for signing only and cannot be used
  for ECDH. (PR #210)
* Object creation fails with `CKR_FUNCTION_FAILED` once the object ids run out
  (about 268 million objects). Session objects now have their own id counter,
  so session object handles start again at 1 after each `C_Initialize`.
  (PR #255)
* After `C_DestroyObject`, `C_FindObjects` can return token objects in a
  different order. PKCS#11 does not define the order. (PR #257)
* MAXQ10xx builds must define `MAXQ10XX_PRODUCTION_KEY`, or
  `WOLFPKCS11_MAXQ10XX_TEST_KEY` to use the built-in test provisioning key.
  With neither the build fails. (PR #207)
* The CMake build now uses hidden symbol visibility and exports only the
  `C_*` functions, like the autotools build. (PR #258)
* A multi-threaded Windows build now needs Windows Vista or later. Windows CE,
  or a `_WIN32_WINNT` below `0x0600`, fails with an `#error`. (PR #254)

**Detail**

* Added verify-only LMS/HSS and XMSS/XMSS^MT support (`--enable-lms`,
  `--enable-xmss`), using the PKCS#11 v3.3 mechanism, key type and attribute
  values. Public keys can be imported, stored and used with `C_Verify`.
  (PR #206)
* Added an option to link a static wolfSSL into libwolfpkcs11 with its symbols
  hidden (`--with-static-wolfssl` in autotools, `WOLFPKCS11_STATIC_WOLFSSL` in
  CMake). The autotools build now also exports the PKCS#11 v3.0 and v3.2
  functions, and the CMake package it installs no longer points at
  `NONE/include` when configured without `--prefix`. (PR #258)
* Creating and destroying token objects now writes only the changed objects
  instead of the whole token, and `C_SetAttributeValue` on a token object
  stores it straight away. (PR #257)
* Fixed ECDH with EC keys generated on a TPM slot. (PR #210)
* Fixed the Windows ABI of the PKCS#11 structures. (PR #209)
* Fixed Windows GCC builds (MinGW-w64, Cygwin, MSYS2) failing on visibility
  attribute warnings. (PR #224)
* Fixed the default Windows token path, which read a variable that does not
  exist. It is now `%APPDATA%\wolfPKCS11`. (PR #225)
* Fixed `WOLFPKCS11_DEFAULT_TOKEN_PATH` being ignored when `HOME` is set, and
  being compiled in with extra quotes when set through configure or CMake.
  (PR #247)
* Fixed NSS database paths with a `sql:`, `dbm:` or `extern:` prefix.
  (PR #219)
* Fixed `C_WrapKey` leaving the operation active after a length query, which
  broke `pk12util -o` through NSS. (PR #220)
* Fixed `C_SetPIN` leaving protected token objects encrypted under the old
  token key, so they could not be read after the next `C_Initialize`.
  (PR #226)
* Fixed `CKA_CHECK_VALUE` for AES-192 keys and generic secret keys.
  (PR #248)
* Fixed `C_GetAttributeValue` failing the whole template for attributes an
  object does not have. (PR #222)
* Fixed object handles colliding with token object handles once object ids
  passed `0x0FFFFFFF`, which could read or destroy the wrong object.
  (PR #255)
* Fixed a double free when two sessions destroy the same token object at the
  same time. (PR #205)
* Fixed `C_DestroyObject` removing another object that had been created at
  the same address by another thread. (PR #252)
* Fixed the internal read/write lock being released by a thread that did not
  take it, which hung `pkcs11mtt` under Wine, and fixed the data races
  ThreadSanitizer reported. (PR #254)
* Fixed a memory leak when `C_Login` decodes keys that are already loaded.
  With a wolfSSL built with `HAVE_WOLF_BIGINT` (for example
  `--enable-pkcs11`), RSA and ECC keys leaked their big integers, and with
  dynamic key buffers ML-DSA and ML-KEM keys leaked their key buffers. A new
  ASAN CI build against such a wolfSSL catches this. (PR #261)
* Fixed building the AES key wrap with padding code against FIPS v5.2
  modules. (PR #217)
* Fixed the wolfTPM build with `WOLFPKCS11_NO_STORE`. (PR #246)
* Fixed numerous PKCS#11 compliance, memory-safety and concurrency findings
  from Fenrir static analysis. (PR #207, PR #212, PR #213, PR #214, PR #215,
  PR #216, PR #227, PR #243) These include:
  * Access control and login state: private objects are limited to user
    sessions, login lockout counts stop at the limit and also cover
    `C_SetPIN`, a failed login clears the derived token key, and logout
    protects every decoded token object.
  * Stored objects: object policy is bound to the encrypted key data, stored
    records are validated before use, store failures are reported and rolled
    back, fresh IVs are generated before keys are stored, HKDF token keys are
    stored, and every object gets a unique `CKA_UNIQUE_ID`.
  * Operation state: operations are released when replaced, cancelled or
    ending in an error, `CKR_BUFFER_TOO_SMALL` reports the needed length and
    keeps the operation for a retry, and lengths that do not fit in 32 bits
    are rejected.
  * Mechanism parameters: AES-CTR counter, AES-GCM, AES-CCM, OAEP, PSS, CMAC,
    ECDH, DH, HKDF and TLS derive parameters are checked, and derived keys
    take their `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` values from
    the base key.
  * Templates: attributes are validated before an object is changed, key
    material and certificate values are fixed after creation, data objects
    are copied and partly updated correctly, and NSS email attributes are
    sized correctly in the store.
  * Information functions: fixed-length fields in `C_GetInfo`,
    `C_GetSlotInfo` and `C_GetTokenInfo` are blank padded, and mechanism
    flags and key sizes match what is implemented. SSL 3.0 key derivation is
    no longer advertised.
  * Key material and transient MAC, AES and RNG buffers are zeroized after
    use and on error paths.
* `--enable-singlethreaded` now defines `WOLFPKCS11_SINGLE_THREADED` instead
  of wolfSSL's `SINGLE_THREADED`, so wolfPKCS11 uses the same wolfSSL
  structure layout as a multi-threaded libwolfssl. (PR #243)
* Enabled ThreadSanitizer in CI. (PR #254)
* Fixed linking the tests in C++ debug builds. (PR #256, PR #259)
* Renamed `ecb_check_value_error_test` to `generic_secret_check_value_test`.
  (PR #250)
* Updated the wolfBoot emulator CI image to m33mu v1.25. (PR #249)
* Added `CONTRIBUTING.md`. (PR #211)
* Added the 2.1 release date to the README. (PR #203)
* The shared library version is now 4.1.0, as the library exports the
  PKCS#11 v3.0 and v3.2 functions.
* Thanks to Peter Dennis Bartok for reporting the `C_GetAttributeValue` and
  `CKA_CHECK_VALUE` issues (issue #221, issue #245) and to Nazar Serhiichuk
  for reporting the Windows ABI issue (issue #208).

### wolfPKCS11 Release 2.1 (Jun 25, 2026)

**Summary**

This release adds post-quantum cryptography support (ML-DSA and ML-KEM), CMake
build support, and Doxygen API documentation. It also closes a large number of
PKCS#11 specification compliance gaps and bugs found through static and
negative analysis, hardens memory safety in response to external security
reports, and improves CI and interoperability testing.

**Compatibility with 2.0 behavior**

Several PKCS#11 attribute defaults were corrected to match the specification.
These changes can affect applications and stored tokens created with 2.0. The
following build defines restore the pre-2.1 (2.0) behavior if needed:

* `WOLFPKCS11_LEGACY_COPYABLE_FALSE_DEFAULT` - restore the old behavior where an
  unset `CKA_COPYABLE` reads back as `CK_FALSE` (the PKCS#11 default is
  `CK_TRUE`).
* `WOLFPKCS11_LEGACY_PRIVATE_FALSE_DEFAULT` - restore the old behavior where an
  unset `CKA_PRIVATE` reads back as `CK_FALSE` for `CKO_PRIVATE_KEY` /
  `CKO_SECRET_KEY` (the PKCS#11 default is `CK_TRUE`). Also disables the
  matching login-state check on object creation.
* `WOLFPKCS11_LEGACY_WRAP_TRUE_DEFAULT` - restore the old behavior where an
  unset `CKA_WRAP` / `CKA_UNWRAP` defaults to `CK_TRUE` (the PKCS#11 default is
  `CK_FALSE`).

See the "Behavior changes for PKCS#11 spec compliance" section above for the
related `C_DeriveKey`, `C_CopyObject`, `C_DestroyObject`, encapsulation and
`C_Login` enforcement changes.

**Detail**

* Added ML-DSA (Dilithium) support, including `CKA_SEED` private key import.
  (PR #161)
* Added ML-KEM support. (PR #175)
* Added preparation work for post-quantum cryptography support. (PR #157)
* Renamed ML-DSA mechanisms/identifiers to the final naming. (PR #188)
* Added CMake build support. (PR #156)
* Added PKCS#11 Doxygen API documentation. (PR #144)
* Added support for `CKR_OPERATION_ACTIVE`. (PR #176)
* Use the DHUK to wrap/unwrap the seed value used for the token. (PR #159)
* Added file storage safety to wolfPKCS11. (PR #150)
* Fixed empty PIN handling for FIPS. (PR #143)
* Fixed loading a token with an empty PIN. (PR #158)
* Fixed SHA-512 truncated forms (SHA-512/224 and SHA-512/256). (PR #147)
* Fixed `C_WrapKey` not checking `CKA_EXTRACTABLE` on the key being wrapped.
  (PR #165)
* Fixed `falseVal` initialized to `CK_TRUE` instead of `CK_FALSE`. (PR #162)
* Fixed a read-only lock not being released on an early return. (PR #163)
* Added a missing NULL check. (PR #166)
* Fixed a typo in an `#ifndef` macro. (PR #167)
* Fixed a typo in `configure.ac`. (PR #164)
* Fixed resource leaks and ensured secure buffer erasing. (PR #172)
* Fixed numerous PKCS#11 compliance and static analysis findings from Fenrir.
  (PR #168, PR #169, PR #171, PR #173, PR #178, PR #185, PR #186, PR #187,
  PR #189, PR #194, PR #196, PR #197, PR #198)
* Hardened memory safety across several operations in response to external
  security reports: bounded the RSA verify-recover output length and validated
  the mechanism and key type before use, bounded secret-key length handling and
  the HKDF derive output length, guarded against length underflow when decoding
  stored symmetric keys, clamped key zeroization, and dropped the active object
  reference on `C_DestroyObject` so completing an operation can no longer read
  freed memory. (PR #201)
* Added negative testing and validation for wolfPKCS11. (PR #179)
* Added Fenrir findings fixes and test additions. (PR #177)
* Added a multi-call HMAC regression test. (PR #181)
* Added a `C_VerifyRecover` test and fixed test attributes. (PR #184)
* Fixed ML-KEM templates in tests. (PR #183)
* Fixed a couple of failing tests. (PR #145)
* Added an interoperability test against wolfSSL master. (PR #148)
* Added a wolfBoot integration test to intercept regressions. (PR #170)
* Reduced the wolfBoot integration test flow (unstable emulator). (PR #174)
* Removed `--enable-cryptocb` usage. (PR #149)
* Fixed CI failures from upstream dependency drift. (PR #180)
* Fixed CI issues. (PR #182)
* Fixed the Firefox Dockerfile. (PR #160)
* Fixed Debian rules for the documentation. (PR #153)
* Fixed `CK_ULONG` length truncation in `C_GenerateRandom` and `C_SeedRandom`.
  (PR #199)
* Fixed the wolfSSL interoperability build by defining
  `WOLFPKCS11_USER_SETTINGS`. (PR #200)
* Updated copyright years and fixed the `configure.ac` start year. (PR #191)
* Shipped the CMake package configuration in the Debian `-dev` package.
  (PR #192)
* Used FIPS-compliant length user PINs across the test suite. (PR #193)
* Added per-job timeouts to all CI workflows. (PR #195)
* Added CI coverage for C++ builds. (PR #190)
* Thanks to Denis Mingulov for contributing the `C_GenerateRandom` /
  `C_SeedRandom` length-truncation fix (PR #199) and for reporting several of
  the memory-safety issues fixed in PR #201 (oversized `CKA_VALUE_LEN`
  handling, the RSA verify-recover output-length type-punning, and the
  use-after-free of an active object on `C_DestroyObject`).

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
