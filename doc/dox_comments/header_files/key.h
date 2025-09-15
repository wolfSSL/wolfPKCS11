/**
 * \page pkcs11_key_overview Key Management
 * Key pair generation, derivation, wrap/unwrap. See PKCS#11 v2.40
 * Section 11.12 "Key Management Functions".
 * - \ref pkcs11_05_key
 */

/*!
 * \ingroup pkcs11_05_key
 * \brief Generate a secret key.
 * 
 * Generates a secret key using the specified mechanism and attributes.
 * See PKCS#11 v2.40 Section 11.12.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_MECHANISM_INVALID or CKR_MECHANISM_PARAM_INVALID if mechanism not supported.
 * \return CKR_TEMPLATE_INCONSISTENT/INCOMPLETE for invalid attributes.
 * \return CKR_SESSION_READ_ONLY for token object in RO session.
 * 
 * \param hSession The session handle.
 * \param pMechanism Mechanism specifying key generation.
 * \param pTemplate Attributes for the new key (e.g., CKA_CLASS, CKA_KEY_TYPE).
 * \param ulCount Number of attributes.
 * \param phKey Output: handle of generated key.
 * 
 * _Example_
 * \code
 * CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
 * CK_KEY_TYPE kt = CKK_AES; CK_BBOOL t = CK_TRUE;
 * CK_ATTRIBUTE tmpl[] = {
 *   {CKA_CLASS, &cls, sizeof(cls)},
 *   {CKA_KEY_TYPE, &kt, sizeof(kt)},
 *   {CKA_TOKEN, &t, sizeof(t)},
 *   {CKA_ENCRYPT, &t, sizeof(t)}, {CKA_DECRYPT, &t, sizeof(t)}
 * };
 * CK_MECHANISM mech = {CKM_AES_KEY_GEN, NULL_PTR, 0};
 * CK_OBJECT_HANDLE hKey;
 * CK_RV rv = C_GenerateKey(hSession, &mech, tmpl, sizeof(tmpl)/sizeof(tmpl[0]), &hKey);
 * \endcode
 */
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);

/*!
 * \ingroup pkcs11_05_key
 * \brief Generate a public/private key pair.
 * 
 * Generates a key pair with separate attribute templates for public and
 * private keys. See Section 11.12.2.
 * 
 * \return CKR_OK on success; template/mechanism errors otherwise.
 * \param hSession The session handle.
 * \param pMechanism Mechanism specifying key pair generation (e.g., CKM_EC_KEY_PAIR_GEN).
 * \param pPublicKeyTemplate Public key attributes.
 * \param ulPublicKeyAttributeCount Number of public attributes.
 * \param pPrivateKeyTemplate Private key attributes.
 * \param ulPrivateKeyAttributeCount Number of private attributes.
 * \param phPublicKey Output public key handle.
 * \param phPrivateKey Output private key handle.
 * 
 * _Example_
 * \code
 * CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
 * CK_BBOOL t = CK_TRUE;
 * CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};
 * CK_UTF8CHAR curve[] = "P-256";
 * CK_ATTRIBUTE pubTmpl[] = {
 *   {CKA_CLASS, &pubClass, sizeof(pubClass)},
 *   {CKA_EC_PARAMS, curve, sizeof(curve)-1},
 *   {CKA_VERIFY, &t, sizeof(t)}
 * };
 * CK_ATTRIBUTE privTmpl[] = {
 *   {CKA_CLASS, &privClass, sizeof(privClass)},
 *   {CKA_TOKEN, &t, sizeof(t)},
 *   {CKA_PRIVATE, &t, sizeof(t)},
 *   {CKA_SIGN, &t, sizeof(t)}
 * };
 * CK_OBJECT_HANDLE hPub, hPriv;
 * CK_RV rv = C_GenerateKeyPair(hSession, &mech,
 *     pubTmpl, sizeof(pubTmpl)/sizeof(pubTmpl[0]),
 *     privTmpl, sizeof(privTmpl)/sizeof(privTmpl[0]),
 *     &hPub, &hPriv);
 * \endcode
 */
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);

/*!
 * \ingroup pkcs11_05_key
 * \brief Wrap (export) a key with another key.
 * 
 * Wraps a key using a wrapping key and mechanism, returning wrapped bytes.
 * Use two-call pattern to size the output. See Section 11.12.3.
 * 
 * \return CKR_OK on success; CKR_BUFFER_TOO_SMALL if output too small.
 * \return CKR_KEY_HANDLE_INVALID; CKR_WRAP_MODE_INVALID; CKR_WRAPPING_KEY_SIZE_RANGE.
 * 
 * \param hSession The session handle.
 * \param pMechanism Wrapping mechanism (e.g., CKM_AES_KEY_WRAP).
 * \param hWrappingKey Wrapping key handle.
 * \param hKey Key handle to wrap (must be CKA_EXTRACTABLE).
 * \param pWrappedKey Output buffer for wrapped bytes (may be NULL_PTR).
 * \param pulWrappedKeyLen Pointer to wrapped length.
 */
CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);

/*!
 * \ingroup pkcs11_05_key
 * \brief Unwrap (import) a key using another key.
 * 
 * Creates a key object from wrapped bytes using the unwrapping key and
 * attributes. See Section 11.12.4.
 * 
 * \return CKR_OK on success; CKR_WRAPPED_KEY_INVALID on parse/verify failure.
 * \param hSession The session handle.
 * \param pMechanism Unwrap mechanism.
 * \param hUnwrappingKey Unwrapping key handle.
 * \param pWrappedKey Wrapped bytes.
 * \param ulWrappedKeyLen Length of wrapped bytes.
 * \param pTemplate Attributes for the unwrapped key.
 * \param ulAttributeCount Number of attributes.
 * \param phKey Output unwrapped key handle.
 */
CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);

/*!
 * \ingroup pkcs11_05_key
 * \brief Derive a key from a base key.
 * 
 * Derives a key using the specified derivation mechanism and attributes.
 * See Section 11.12.5.
 * 
 * \return CKR_OK on success; CKR_MECHANISM_PARAM_INVALID otherwise.
 * \param hSession The session handle.
 * \param pMechanism Derivation mechanism (e.g., CKM_ECDH1_DERIVE).
 * \param hBaseKey Base key handle.
 * \param pTemplate Attributes for the derived key.
 * \param ulAttributeCount Number of attributes.
 * \param phKey Output derived key handle.
 * 
 * _Example_
 * \code
 * CK_ECDH1_DERIVE_PARAMS params = {CKD_NULL, NULL, 0, otherPub, otherPubLen};
 * CK_MECHANISM mech = {CKM_ECDH1_DERIVE, &params, sizeof(params)};
 * CK_OBJECT_HANDLE hDerived;
 * CK_ATTRIBUTE_PTR tmpl = NULL;
 * CK_ULONG tmplCount = 0;
 * CK_RV rv = C_DeriveKey(hSession, &mech, hPrivKey, tmpl, tmplCount, &hDerived);
 * \endcode
 */
CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
