/**
 * \mainpage wolfPKCS11 Documentation
 *
 * \section intro Introduction
 *
 * wolfPKCS11 is a PKCS#11 (Cryptoki) implementation backed by wolfSSL's
 * wolfCrypt. It provides a standard API for cryptographic tokens such as HSMs,
 * smart cards, and software tokens.
 *
 * \section scope Scope
 *
 * This documentation focuses on the public PKCS#11 API exposed by
 * wolfPKCS11 via wolfpkcs11/pkcs11.h. Functions are organized into logical
 * groups that follow the typical PKCS#11 application workflow.
 *
 * \section api_groups API Organization
 *
 * The PKCS#11 API is organized into the following functional groups,
 * listed in the typical order of use:
 *
 * 1. **\ref pkcs11_01_core "Core"** - Library initialization and finalization
 * 2. **\ref pkcs11_02_slot_token "SlotsAndTokens"** - Slot and token management
 * 3. **\ref pkcs11_03_session "Sessions"** - Session management and authentication
 * 4. **\ref pkcs11_04_object "Objects"** - Object creation and management
 * 5. **\ref pkcs11_05_key "KeyManagement"** - Key generation and key operations
 * 6. **\ref pkcs11_06_random "Random"** - Random number generation
 * 7. **\ref pkcs11_07_digest "Digest"** - Message digest operations
 * 8. **\ref pkcs11_08_encrypt_decrypt "EncryptDecrypt"** - Encryption and decryption
 * 9. **\ref pkcs11_09_sign_verify "SignVerify"** - Digital signatures
 * 10. **\ref pkcs11_10_extensions "wolfPKCS11 Extensions"** - wolfPKCS11-specific extensions
 *
 * \section getting_started Getting Started
 *
 * The typical application flow follows these steps:
 *
 * \code
 * // 1. Get the function list
 * CK_FUNCTION_LIST_PTR p11;
 * rv = C_GetFunctionList(&p11);
 *
 * // 2. Initialize the library
 * rv = p11->C_Initialize(NULL_PTR);
 *
 * // 3. Get available slots
 * rv = p11->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
 *
 * // 4. Open a session
 * rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
 *                         NULL_PTR, NULL_PTR, &hSession);
 *
 * // 5. Login if required
 * rv = p11->C_Login(hSession, CKU_USER, pin, pinLen);
 *
 * // 6. Create or find objects (keys, certificates)
 * rv = p11->C_FindObjectsInit(hSession, template, templateCount);
 *
 * // 7. Perform cryptographic operations
 * rv = p11->C_EncryptInit(hSession, &mechanism, hKey);
 * rv = p11->C_Encrypt(hSession, plaintext, plaintextLen, ciphertext, &ciphertextLen);
 *
 * // 8. Cleanup
 * rv = p11->C_Logout(hSession);
 * rv = p11->C_CloseSession(hSession);
 * rv = p11->C_Finalize(NULL_PTR);
 * \endcode
 *
 * \section workflow Application Workflow
 *
 * ### Initialization Phase
 * - Use \ref pkcs11_01_core "Core" functions to initialize the library
 * - Use \ref pkcs11_02_slot_token "SlotsAndTokens" functions to discover available tokens
 * - Use \ref pkcs11_03_session "Sessions" functions to establish a session
 *
 * ### Setup Phase
 * - Use \ref pkcs11_04_object "Objects" functions to find existing keys/certificates
 * - Use \ref pkcs11_05_key "KeyManagement" functions to generate new keys if needed
 * - Use \ref pkcs11_06_random "Random" functions for nonce generation
 *
 * ### Operations Phase
 * - Use \ref pkcs11_07_digest "Digest" functions for hashing
 * - Use \ref pkcs11_08_encrypt_decrypt "EncryptDecrypt" functions for data protection
 * - Use \ref pkcs11_09_sign_verify "SignVerify" functions for authentication
 *
 * ### Cleanup Phase
 * - Close sessions and finalize the library
 *
 * \section extensions wolfPKCS11 Extensions
 *
 * wolfPKCS11 provides several extensions beyond the standard PKCS#11 specification:
 * - Use \ref pkcs11_10_extensions "wolfPKCS11 Extensions" for debugging and wolfSSL integration
 * - Debug logging functions for troubleshooting
 * - Custom attributes for wolfSSL crypto callback integration
 * - STM32U5 DHUK support for hardware-specific features
 * - NSS compatibility extensions:
 *   - See \ref pkcs11_nss_extensions_overview "NSS Extensions Overview"
 *   - \ref pkcs11_nss_mechanisms "NSS Mechanisms"
 *   - \ref pkcs11_nss_objects "NSS Object Types"
 *   - \ref pkcs11_nss_attributes "NSS Attributes"
 *   - \ref pkcs11_nss_structures "NSS Parameter Structures"
 *   - \ref pkcs11_nss_examples "NSS Extension Examples"
 *   - \ref pkcs11_nss_compatibility "NSS Compatibility Notes"
 *
 * \section data_structs Data Structures
 *
 * For definitions of the PKCS#11 data structures supported by wolfPKCS11, see \ref data_structures.h "data_structures.h". These populate Doxygen's "Data Structure Index" and "Data Structure Documentation".
 *
 * \section standards Standards Compliance
 *
 * wolfPKCS11 implements PKCS#11 v2.40 specification. For detailed information
 * about the standard, refer to the OASIS PKCS#11 Cryptographic Token Interface Standard
 *
 * \section support Support and Examples
 *
 * For additional help:
 * - Check the examples/ directory for sample applications
 * - Visit wolfSSL documentation at docs.wolfssl.com
 * - Contact wolfSSL support for commercial licensing and support
 */
