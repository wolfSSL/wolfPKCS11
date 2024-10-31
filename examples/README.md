# Examples of using PKCS#11 API

These examples show how to do common operations with a PKCS#11 token.

## init_token

Initialize the token and set the passwords for the Security Officer (SO) and
User.

```
  ./examples/init_token
```

Steps (see pkcs11_init_token):
  1. Initialize token with Securtiy Officer's (SO) Pin and a label using
     C_InitToken.
  2. Open a session on the token with C_OpenSession.
  3. Login to the token with SO's PIN using C_Login
  4. Initialize the User's PIN with C_InitPin


## slot_info

Show the slot information.

```
  ./examples/slot_into
```

pkcs11_slot_info() uses C_GetSlotInfo to get the data structure and prints the
slot's information as text.

## token_info

Show the token information.

```
  ./examples/token_info
```

pkcs11_token_info() uses C_GetTokenInfo to get the data structure and prints the
token's information as text.

## mech_info

Show information on mechanism of slot.

```
  ./examples/mech_info
```

pkcs11_mechs_info() shows all mechanisms available for a slot. Calls
C_GetMechanismList to get all avaialble mechanisms.

pkcs11_mech_info() retrieves the mechanism's info with C_GetMechanismInfo and
prints it.


## add_aes_key

Adds an AES key to the PKCS#11 Store. Key will only available for the session
unless a private identifier is supplied.

Store in session:

```
  ./examples/add_aes_key
```

Store on token:

```
  ./examples/add_aes_key -privId <label>
```

pkcs11_add_aes_key() uses C_CreateObject to store the key in the PKCS#11 store.
Key type attribute should CKK_AES if supported.

## add_hmac_key

Adds an HMAC key to the PKCS#11 Store. Key will only available for the
session unless a private identifier is supplied.

Store in session:

```
  ./examples/add_hmac_key
```

Store on token:

```
  ./examples/add_hmac_key -privId <label>
```

pkcs11_add_hmac_key() uses C_CreateObject to store the key in the PKCS#11 store.
Key type attribute is CKK_GENERIC_SECRET.

## add_rsa_key

Adds an RSA key to the PKCS#11 Store. Key will only available for the
session unless a private identifier is supplied.

Store in session:

```
  ./examples/add_rsa_key
```

Store on token:

```
  ./examples/add_rsa_key -privId <label>
```

pkcs11_add_rsa_key() uses C_CreateObject to store the key in the PKCS#11 store.


## add_rsa_key_file

Adds an RSA key from a DER encoded file to the PKCS#11 Store. Key will only
available for the session unless a private identifier is supplied.

Store in session:

```
  ./examples/add_rsa_key_file -rsa <filename>
```

Store on token:

```
  ./examples/add_rsa_key_file -privId <label> -rsa <filename>
```

load_rsa_key() loads the DER encoded RSA private key from file into an RsaKey
object.

pkcs11_add_rsa_key() uses C_CreateObject to store the key in the PKCS#11 store.

export_mp() is used get the data for each of the private key components.


## obj_list

Lists the objects stored on a token.


```
  ./examples/obj_list
```

pkcs11_objs_attr() finds all objects using C_FindObjectsInit(), C_FindObjects()
and C_FindObjectsFinal() and prints them.

pkcs11_obj_attr() uses C_GetAttributeValue() to get the attribute values of an
object that is identified by its handle.

pkcs11_key_attr() uses C_GetAttributeValue() to get common attriubtes of keys.

pkcs11_rsa_attr() uses C_GetAttributeValue() to get the public fields of an RSA
key.

