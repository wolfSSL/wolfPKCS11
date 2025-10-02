/**
 * \defgroup pkcs11_01_core Core
 * Core library initialization and finalization functions.
 * 
 * These functions handle the basic lifecycle of the PKCS#11 library.
 * Start here: C_Initialize() must be called before any other functions.
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_structs Data Structures
 * PKCS#11 data structures supported by wolfPKCS11.
 *
 * These types include core Cryptoki structures (e.g., CK_INFO, CK_SLOT_INFO,
 * CK_TOKEN_INFO, CK_SESSION_INFO, CK_ATTRIBUTE, CK_MECHANISM, CK_RSA_PKCS_PSS_PARAMS,
 * CK_RSA_PKCS_OAEP_PARAMS, CK_ECDH1_DERIVE_PARAMS, CK_GCM_PARAMS, CK_CCM_PARAMS,
 * CK_TLS12_MASTER_KEY_DERIVE_PARAMS, CK_SSL3_KEY_MAT_OUT, CK_TLS12_KEY_MAT_PARAMS,
 * CK_PKCS5_PBKD2_PARAMS, CK_PKCS5_PBKD2_PARAMS2, CK_TLS_MAC_PARAMS) and related
 * scalar typedefs. Detailed per-structure docs are provided in header_files.
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_02_slot_token SlotsAndTokens
 * Slot and token discovery and management.
 * 
 * Functions to enumerate available slots, get token information,
 * and manage token state.
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_03_session Sessions
 * Session management and authentication.
 * 
 * Functions to open/close sessions, login/logout, and manage
 * session state and operations.
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_04_object Objects
 * Object creation, discovery, and attribute management.
 * 
 * Functions to create, find, destroy, and manipulate cryptographic
 * objects such as keys and certificates.
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_05_key KeyManagement
 * Key generation, derivation, and wrapping operations.
 * 
 * Functions for generating symmetric and asymmetric keys,
 * deriving keys, and wrapping/unwrapping key material.
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_06_random Random
 * Random number generation and entropy seeding.
 * 
 * Functions to generate random data and seed the random
 * number generator.
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_07_digest Digest
 * Message digest and hashing operations.
 * 
 * Functions for computing cryptographic hashes and message
 * authentication codes (MACs).
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_08_encrypt_decrypt EncryptDecrypt
 * Symmetric and asymmetric encryption/decryption.
 * 
 * Functions for encrypting and decrypting data using various
 * symmetric and asymmetric algorithms.
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_09_sign_verify SignVerify
 * Digital signature creation and verification.
 * 
 * Functions for creating and verifying digital signatures
 * using various signature algorithms.
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_10_extensions wolfPKCS11 Extensions
 * wolfPKCS11-specific extensions to the PKCS#11 specification.
 * 
 * These functions and features are specific to wolfPKCS11 and extend
 * the standard PKCS#11 API with additional functionality for debugging,
 * configuration, and wolfSSL integration.
 * @{
 * \}
 */

/**
 * \defgroup pkcs11_nss_extensions_overview NSS Extensions
 * Mozilla NSS compatibility extensions for wolfPKCS11.
 * 
 * These extensions provide compatibility with Mozilla NSS (Network Security
 * Services) and enable wolfPKCS11 to be used as a drop-in replacement for
 * NSS's PKCS#11 module. Features include NSS-specific mechanisms for TLS
 * operations, trust objects for certificate management, and PKCS#12 PBE
 * key generation.
 * 
 * NSS extensions are enabled using the --enable-nss configure flag.
 * @{
 * \}
 */