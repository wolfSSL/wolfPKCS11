## wolfPKCS11 Tests

The test files have the following purposes:
* `pkcs11test.c`: is the standard tests
* `pkcs11mtt.c`: is the multithreaded tests
* `pkcs11str.c`: is a storage test
* `debug_test.c`: is a debug functionality demonstration test
* `custom_store_test.c`: is a custom store (`WOLFPKCS11_CUSTOM_STORE`) test. It
  builds the library sources in, with and without
  `WOLFPKCS11_CUSTOM_STORE_CLOSE_COMMIT`
