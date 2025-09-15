/**
 * \page pkcs11_extensions_overview wolfPKCS11 Extensions
 * wolfPKCS11-specific extensions and enhancements to the standard PKCS#11 API.
 * 
 * wolfPKCS11 provides several extensions beyond the standard PKCS#11 specification
 * to enable better integration with wolfSSL, enhanced debugging capabilities, and
 * additional configuration options.
 * - \ref pkcs11_10_extensions
 */

/*!
 * \ingroup pkcs11_10_extensions
 * \brief Enable debug logging for wolfPKCS11.
 * 
 * Enables detailed debug output from wolfPKCS11 operations. This function
 * activates internal logging that can help with troubleshooting and development.
 * Debug output is sent to stderr by default.
 * 
 * \note This function is only available when wolfPKCS11 is compiled with
 *       DEBUG_WOLFPKCS11 defined. When debug support is disabled, this
 *       function becomes a no-op macro.
 * 
 * \note Debug logging may expose sensitive information including key material
 *       and should only be enabled in development environments.
 * 
 * _Example_
 * \code
 * #ifdef DEBUG_WOLFPKCS11
 * // Enable debug logging before initializing PKCS#11
 * wolfPKCS11_Debugging_On();
 * #endif
 * 
 * CK_RV rv = C_Initialize(NULL_PTR);
 * if (rv != CKR_OK) {
 *     printf("C_Initialize failed: 0x%08lX\n", rv);
 * }
 * 
 * // ... perform operations with debug output ...
 * 
 * #ifdef DEBUG_WOLFPKCS11
 * wolfPKCS11_Debugging_Off();
 * #endif
 * \endcode
 * 
 * \sa wolfPKCS11_Debugging_Off
 */
void wolfPKCS11_Debugging_On(void);

/*!
 * \ingroup pkcs11_10_extensions
 * \brief Disable debug logging for wolfPKCS11.
 * 
 * Disables debug output from wolfPKCS11 operations. This function turns off
 * internal logging that was previously enabled with wolfPKCS11_Debugging_On().
 * 
 * \note This function is only available when wolfPKCS11 is compiled with
 *       DEBUG_WOLFPKCS11 defined. When debug support is disabled, this
 *       function becomes a no-op macro.
 * 
 * _Example_
 * \code
 * #ifdef DEBUG_WOLFPKCS11
 * wolfPKCS11_Debugging_On();
 * #endif
 * 
 * // ... perform operations with debug output ...
 * 
 * #ifdef DEBUG_WOLFPKCS11
 * // Disable debug logging when done
 * wolfPKCS11_Debugging_Off();
 * #endif
 * 
 * C_Finalize(NULL_PTR);
 * \endcode
 * 
 * \sa wolfPKCS11_Debugging_On
 */
void wolfPKCS11_Debugging_Off(void);

/*!
 * \ingroup pkcs11_10_extensions
 * \brief wolfSSL device ID attribute for crypto callbacks.
 * 
 * This vendor-defined attribute (CKA_WOLFSSL_DEVID) allows setting a specific
 * wolfSSL crypto callback device ID to be used with cryptographic objects.
 * This enables integration with hardware acceleration and custom crypto
 * implementations through wolfSSL's crypto callback framework.
 * 
 * The attribute value should be a CK_ULONG containing the device ID.
 * 
 * _Example_
 * \code
 * CK_ATTRIBUTE template[] = {
 *     {CKA_CLASS,          &keyClass,    sizeof(keyClass)},
 *     {CKA_KEY_TYPE,       &keyType,     sizeof(keyType)},
 *     {CKA_WOLFSSL_DEVID,  &deviceId,    sizeof(deviceId)},
 *     // ... other attributes
 * };
 * 
 * CK_RV rv = C_CreateObject(hSession, template, 
 *                          sizeof(template)/sizeof(template[0]), 
 *                          &hKey);
 * \endcode
 * 
 * \sa CKA_WOLFSSL_DHUK_IV
 */
#define CKA_WOLFSSL_DEVID

/*!
 * \ingroup pkcs11_10_extensions
 * \brief STM32U5 DHUK initialization vector attribute.
 * 
 * This vendor-defined attribute (CKA_WOLFSSL_DHUK_IV) is specific to STM32U5
 * devices and allows setting the initialization vector for DHUK (Device
 * Hardware Unique Key) operations.
 * 
 * \note This attribute is only available when compiled with WOLFSSL_STM32U5_DHUK
 *       defined, which enables STM32U5-specific DHUK functionality.
 * 
 * _Example_
 * \code
 * #ifdef WOLFSSL_STM32U5_DHUK
 * CK_BYTE dhukIv[16] = { /* IV bytes */ };
 * CK_ATTRIBUTE template[] = {
 *     {CKA_CLASS,           &keyClass,  sizeof(keyClass)},
 *     {CKA_WOLFSSL_DHUK_IV, dhukIv,     sizeof(dhukIv)},
 *     // ... other attributes
 * };
 * #endif
 * \endcode
 * 
 * \sa CKA_WOLFSSL_DEVID
 */
#define CKA_WOLFSSL_DHUK_IV

/*!
 * \ingroup pkcs11_10_extensions
 * \brief wolfSSL vendor ID for vendor-defined extensions.
 * 
 * This constant (CK_VENDOR_WOLFSSL_DEVID = 0x574F4C46L) defines the vendor ID
 * used by wolfSSL for all vendor-defined PKCS#11 extensions. The value spells
 * "WOLF" in ASCII when viewed as bytes.
 * 
 * This vendor ID is used as the base for constructing vendor-defined attribute
 * and mechanism type identifiers according to the PKCS#11 specification.
 * 
 * \sa CKA_WOLFSSL_DEVID
 * \sa CKA_WOLFSSL_DHUK_IV
 */
#define CK_VENDOR_WOLFSSL_DEVID