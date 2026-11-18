/* hbs.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * wolfPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Hash-based signature key support. */

#ifndef WOLFPKCS11_HBS_H
#define WOLFPKCS11_HBS_H

#include "wp11_types.h"

#ifdef WOLFPKCS11_LMS

#ifndef WOLFPKCS11_NO_STORE
WP11_LOCAL int wp11_Object_Encode_HssKey(WP11_Object* object);
WP11_LOCAL int wp11_Object_Decode_HssKey(WP11_Object* object);
WP11_LOCAL int wp11_Object_Load_HssKey(WP11_Object* object, int tokenId,
                                       int objId);
WP11_LOCAL int wp11_Object_Store_HssKey(WP11_Object* object, int tokenId,
                                        int objId);
#endif
WP11_LOCAL int wp11_HssObject_GetAttr(WP11_Object* object,
                                      CK_ATTRIBUTE_TYPE type,
                                      byte* data, CK_ULONG* len);
WP11_LOCAL int wp11_HssCheckTypesAttr(WP11_Object* object,
                                      CK_ATTRIBUTE_TYPE type, const byte* data,
                                      CK_ULONG len);

#endif /* WOLFPKCS11_LMS */

#ifdef WOLFPKCS11_XMSS

#ifndef WOLFPKCS11_NO_STORE
WP11_LOCAL int wp11_Object_Encode_XmssKey(WP11_Object* object);
WP11_LOCAL int wp11_Object_Decode_XmssKey(WP11_Object* object);
WP11_LOCAL int wp11_Object_Load_XmssKey(WP11_Object* object, int tokenId,
                                        int objId);
WP11_LOCAL int wp11_Object_Store_XmssKey(WP11_Object* object, int tokenId,
                                         int objId);
#endif
WP11_LOCAL int wp11_XmssObject_GetAttr(WP11_Object* object,
                                       CK_ATTRIBUTE_TYPE type,
                                       byte* data, CK_ULONG* len);

#endif /* WOLFPKCS11_XMSS */

#endif /* WOLFPKCS11_HBS_H */
