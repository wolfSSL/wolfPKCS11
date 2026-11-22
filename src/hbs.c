/* hbs.c
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

/* LMS/HSS (RFC 8554) and XMSS/XMSS^MT (RFC 8391) hash-based signatures. */

#include "wp11_types.h"
#include "hbs.h"

#if defined(WOLFPKCS11_XMSS) || defined(WOLFPKCS11_STATEFUL_SIG_PRIVATE)
static word32 wp11_HbsReadU32(const byte* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16)
         | ((word32)p[2] << 8)  |  (word32)p[3];
}
#endif

#ifdef WOLFPKCS11_STATEFUL_SIG_PRIVATE
static word64 wp11_Stateful_ReadU64(const byte* p)
{
    return ((word64)p[0] << 56) | ((word64)p[1] << 48)
         | ((word64)p[2] << 40) | ((word64)p[3] << 32)
         | ((word64)p[4] << 24) | ((word64)p[5] << 16)
         | ((word64)p[6] << 8)  |  (word64)p[7];
}

static void wp11_Stateful_WriteU32(byte* p, word32 v)
{
    p[0] = (byte)(v >> 24);
    p[1] = (byte)(v >> 16);
    p[2] = (byte)(v >> 8);
    p[3] = (byte)v;
}

static void wp11_Stateful_WriteU64(byte* p, word64 v)
{
    p[0] = (byte)(v >> 56);
    p[1] = (byte)(v >> 48);
    p[2] = (byte)(v >> 40);
    p[3] = (byte)(v >> 32);
    p[4] = (byte)(v >> 24);
    p[5] = (byte)(v >> 16);
    p[6] = (byte)(v >> 8);
    p[7] = (byte)v;
}

#define WP11_STATEFUL_SALT_LEN        16
/* Caps that keep the size arithmetic below from overflowing. */
#define WP11_STATEFUL_PRIV_MAX        (1U << 20)
#define WP11_STATEFUL_SHELL_MAX       1024U
#define WP11_STATEFUL_POLICY_MAX      64U

#define WP11_STATEFUL_KIND_SEALED     0U

/* Record: [u32 len][shell][u32 kind], then [u32 len][policy][u64 count][salt]
 * [u32 len][ct], sealed up to the salt. */
typedef struct WP11_StatefulRec {
    const byte* rec;
    const byte* shell;
    word32 shellLen;
    word32 kind;
    const byte* policy;
    word32 policyLen;
    word64 count;
    word32 aadLen;
    const byte* salt;
    const byte* ct;
    word32 ctLen;
} WP11_StatefulRec;

#define WP11_STATEFUL_SHELL_BUF       256U

/* The steps that differ between the stateful schemes. */
typedef struct WP11_StatefulOps {
    int (*shell)(WP11_Object* o, byte* shell, word32* shellLen);
    int (*load)(WP11_Object* o, const byte* rec, word32 len, int reload);
    int (*sign)(WP11_Object* o, byte* sig, word32* sigLen, const byte* msg,
        word32 msgLen);
    int (*total)(WP11_Object* o, word64* total); /* 0: over 64 bits */
    int (*broken)(WP11_Object* o);
} WP11_StatefulOps;

/* A zero token key means no user key is loaded. */
static int wp11_Stateful_KeyIsZero(const byte* key, int keySz)
{
    byte acc = 0;
    int i;

    for (i = 0; i < keySz; i++)
        acc |= key[i];
    return acc == 0;
}

static int wp11_Stateful_Parse(const byte* rec, word32 len,
    WP11_StatefulRec* r)
{
    word32 idx;
    word32 n;

    XMEMSET(r, 0, sizeof(*r));
    r->rec = rec;
    if (rec == NULL || len < 12)
        return BAD_FUNC_ARG;
    n = wp11_HbsReadU32(rec);
    idx = 4;
    if (n == 0 || n > WP11_STATEFUL_SHELL_MAX || n > len - idx - 4)
        return BAD_FUNC_ARG;
    r->shell = rec + idx;
    r->shellLen = n;
    idx += n;
    r->kind = wp11_HbsReadU32(rec + idx);
    idx += 4;

    if (r->kind != WP11_STATEFUL_KIND_SEALED || len - idx < 4)
        return BAD_FUNC_ARG;
    n = wp11_HbsReadU32(rec + idx);
    idx += 4;
    if (n > WP11_STATEFUL_POLICY_MAX ||
            len - idx < n + 8 + WP11_STATEFUL_SALT_LEN + 4) {
        return BAD_FUNC_ARG;
    }
    r->policy = rec + idx;
    r->policyLen = n;
    idx += n;
    r->count = wp11_Stateful_ReadU64(rec + idx);
    idx += 8;
    r->aadLen = idx;
    r->salt = rec + idx;
    idx += WP11_STATEFUL_SALT_LEN;
    n = wp11_HbsReadU32(rec + idx);
    idx += 4;
    if (n <= AES_BLOCK_SIZE || n - AES_BLOCK_SIZE > WP11_STATEFUL_PRIV_MAX ||
            n != len - idx) {
        return BAD_FUNC_ARG;
    }
    r->ct = rec + idx;
    r->ctLen = n;
    return 0;
}

#define WP11_STATEFUL_POLICY_VER      1

/* SHA-256 digest of the attributes that govern use of a key. */
static int wp11_Stateful_PolicyOf(word64 cls, word64 type, word64 mech,
    int local, word32 flags, const byte* tmpl, int tmplLen, byte* digest)
{
    int ret;
    wc_Sha256 sha;
    byte hdr[1 + 3 * 8 + 1 + 4 + 4];
    word32 idx = 0;

    hdr[idx++] = WP11_STATEFUL_POLICY_VER;
    wp11_Stateful_WriteU64(hdr + idx, cls);
    idx += 8;
    wp11_Stateful_WriteU64(hdr + idx, type);
    idx += 8;
    wp11_Stateful_WriteU64(hdr + idx, mech);
    idx += 8;
    hdr[idx++] = (byte)local;
    wp11_Stateful_WriteU32(hdr + idx,
        flags & ~(word32)WP11_STATEFUL_POLICY_SKIP);
    idx += 4;
    wp11_Stateful_WriteU32(hdr + idx, (word32)tmplLen);

    ret = wc_InitSha256(&sha);
    if (ret == 0) {
        ret = wc_Sha256Update(&sha, hdr, sizeof(hdr));
        if (ret == 0 && tmplLen > 0)
            ret = wc_Sha256Update(&sha, tmpl, (word32)tmplLen);
        if (ret == 0)
            ret = wc_Sha256Final(&sha, digest);
        wc_Sha256Free(&sha);
    }
    return ret;
}

static int wp11_Stateful_Policy(WP11_Object* o, byte* digest)
{
    return wp11_Stateful_PolicyOf((word64)o->objClass, (word64)o->type,
        (word64)o->keyGenMech, (int)o->local, o->opFlag, o->attrTmpl,
        o->attrTmplLen, digest);
}

/* Derive the key of one record from the token key and the record's salt, so
 * the token key itself never seals a record and nonces cannot repeat. */
static int wp11_Stateful_RecordKey(const byte* tokenKey, word32 tokenKeySz,
    const byte* salt, byte* key)
{
    int ret;
    Hmac hmac;
    static const byte label[] = "wolfPKCS11 stateful record";

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_HmacSetKey(&hmac, WC_SHA256, tokenKey, tokenKeySz);
        if (ret == 0)
            ret = wc_HmacUpdate(&hmac, label, (word32)sizeof(label));
        if (ret == 0)
            ret = wc_HmacUpdate(&hmac, salt, WP11_STATEFUL_SALT_LEN);
        if (ret == 0)
            ret = wc_HmacFinal(&hmac, key);
        wc_HmacFree(&hmac);
    }
    wc_ForceZero(&hmac, sizeof(hmac));
    return ret;
}

#ifdef DEBUG_WOLFPKCS11
/* Test hooks that pin the record format. */
WP11_API int WP11_Test_StatefulPolicy(word64 cls, word64 type, word64 mech,
    int local, word32 flags, const byte* tmpl, int tmplLen, byte* digest)
{
    return wp11_Stateful_PolicyOf(cls, type, mech, local, flags, tmpl,
        tmplLen, digest);
}

WP11_API int WP11_Test_StatefulRecordKey(const byte* tokenKey,
    word32 tokenKeySz, const byte* salt, byte* key)
{
    return wp11_Stateful_RecordKey(tokenKey, tokenKeySz, salt, key);
}
#endif

/* Build a record holding priv sealed under key with a fresh salt. */
static int wp11_Stateful_Seal(WP11_Object* o, const byte* shell,
    word32 shellLen, const byte* policy, word32 policyLen, word64 count,
    const byte* priv, word32 privLen, const byte* key, byte** out,
    word32* outLen)
{
    int ret;
    byte* rec;
    word32 idx;
    word32 aadLen;
    word32 len;
    byte recKey[WC_SHA256_DIGEST_SIZE];
    static const byte nonce[GCM_NONCE_MID_SZ] = { 0 };

    if (shellLen == 0 || shellLen > WP11_STATEFUL_SHELL_MAX ||
            policyLen > WP11_STATEFUL_POLICY_MAX || privLen == 0 ||
            privLen > WP11_STATEFUL_PRIV_MAX) {
        return BAD_FUNC_ARG;
    }
    if (wp11_Stateful_KeyIsZero(key, (int)sizeof(o->slot->token.key)))
        return NOT_AVAILABLE_E;

    aadLen = 4 + shellLen + 4 + 4 + policyLen + 8;
    len = aadLen + WP11_STATEFUL_SALT_LEN + 4 + privLen + AES_BLOCK_SIZE;
    rec = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (rec == NULL)
        return MEMORY_E;
    wp11_Stateful_WriteU32(rec, shellLen);
    XMEMCPY(rec + 4, shell, shellLen);
    idx = 4 + shellLen;
    wp11_Stateful_WriteU32(rec + idx, WP11_STATEFUL_KIND_SEALED);
    wp11_Stateful_WriteU32(rec + idx + 4, policyLen);
    idx += 8;
    if (policyLen > 0)
        XMEMCPY(rec + idx, policy, policyLen);
    idx += policyLen;
    wp11_Stateful_WriteU64(rec + idx, count);
    wp11_Stateful_WriteU32(rec + aadLen + WP11_STATEFUL_SALT_LEN,
        privLen + AES_BLOCK_SIZE);

    ret = WP11_Slot_GenerateRandom(o->slot, rec + aadLen,
        WP11_STATEFUL_SALT_LEN);
    if (ret == 0)
        ret = wp11_Stateful_RecordKey(key, (word32)sizeof(o->slot->token.key),
            rec + aadLen, recKey);
    if (ret == 0) {
        ret = wp11_EncryptData(rec + aadLen + WP11_STATEFUL_SALT_LEN + 4,
            priv, (int)privLen, recKey, (int)sizeof(recKey), nonce,
            (int)sizeof(nonce), rec, aadLen, o->devId);
    }
    wc_ForceZero(recKey, sizeof(recKey));
    if (ret != 0) {
        wc_ForceZero(rec, len);
        XFREE(rec, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    *out = rec;
    *outLen = len;
    return 0;
}

/* Decrypt the sealed state of a parsed record into priv. */
static int wp11_Stateful_Unseal(WP11_Object* o, const WP11_StatefulRec* r,
    const byte* key, byte* priv)
{
    int ret;
    byte recKey[WC_SHA256_DIGEST_SIZE];
    static const byte nonce[GCM_NONCE_MID_SZ] = { 0 };

    if (wp11_Stateful_KeyIsZero(key, (int)sizeof(o->slot->token.key)))
        return NOT_AVAILABLE_E;
    ret = wp11_Stateful_RecordKey(key, (word32)sizeof(o->slot->token.key),
        r->salt, recKey);
    if (ret == 0) {
        ret = wp11_DecryptData(priv, r->ct,
            (int)(r->ctLen - AES_BLOCK_SIZE), recKey, (int)sizeof(recKey),
            nonce, (int)sizeof(nonce), r->rec, r->aadLen, o->devId);
    }
    wc_ForceZero(recKey, sizeof(recKey));
    return ret;
}

/* Re-seal a record from oldKey to newKey, with policy when not NULL. */
static int wp11_Stateful_ReSeal(WP11_Object* o, const byte* rec, word32 len,
    const byte* oldKey, const byte* newKey, const byte* policy,
    word32 policyLen, byte** out, word32* outLen)
{
    int ret;
    WP11_StatefulRec r;
    byte* priv = NULL;
    word32 privLen = 0;

    ret = wp11_Stateful_Parse(rec, len, &r);
    if (ret == 0 && r.kind != WP11_STATEFUL_KIND_SEALED)
        ret = BAD_FUNC_ARG;
    if (ret == 0) {
        privLen = r.ctLen - AES_BLOCK_SIZE;
        priv = (byte*)XMALLOC(privLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (priv == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0)
        ret = wp11_Stateful_Unseal(o, &r, oldKey, priv);
    if (ret == 0) {
        if (policy == NULL) {
            policy = r.policy;
            policyLen = r.policyLen;
        }
        ret = wp11_Stateful_Seal(o, r.shell, r.shellLen, policy, policyLen,
            r.count, priv, privLen, newKey, out, outLen);
    }
    if (priv != NULL) {
        wc_ForceZero(priv, privLen);
        XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

/* Write a record so that it is durable before this returns. */
static int wp11_Stateful_Write(int storeType, int tokenId, int objId,
    byte* rec, word32 len)
{
    int ret;
    void* storage = NULL;

    ret = wp11_storage_open(storeType, (CK_ULONG)tokenId, (CK_ULONG)objId,
        (int)len, &storage);
    if (ret == 0) {
        wp11_storage_set_durable(storage, 1);
        ret = wp11_storage_write_array(storage, rec, len);
        ret = wp11_storage_close_write(storage, ret);
    }
    return ret;
}

static int wp11_Stateful_ReadStored(int storeType, int tokenId, int objId,
    byte** rec, int* len)
{
    int ret;
    void* storage = NULL;

    *rec = NULL;
    ret = wp11_storage_open_readonly(storeType, (CK_ULONG)tokenId,
        (CK_ULONG)objId, &storage);
    if (ret == 0) {
        ret = wp11_storage_read_alloc_array(storage, rec, len);
        wp11_storage_close(storage);
    }
    return ret;
}

static int wp11_Stateful_SameKey(const WP11_StatefulRec* a,
    const WP11_StatefulRec* b)
{
    return a->kind == b->kind && a->shellLen == b->shellLen &&
        XMEMCMP(a->shell, b->shell, a->shellLen) == 0;
}

/* Errors of wp11_Stateful_Adopt that mean the stored record is missing or
 * damaged. */
static int wp11_Stateful_Damaged(int ret)
{
    return ret == NOT_AVAILABLE_E || ret == BUFFER_E || ret == ASN_PARSE_E ||
        ret == BAD_FUNC_ARG || ret == BAD_STATE_E;
}

static int wp11_Stateful_StoreType(WP11_Object* o)
{
    (void)o;
    return WOLFPKCS11_STORE_HSSKEY_PRIV;
}

/* Bring o up to the record at objId, or reload it with force, refusing a state
 * behind memory or of another key. Caller holds the state lock. */
static int wp11_Stateful_Refresh(WP11_Object* o, int storeType, int objId,
    int force, const WP11_StatefulOps* ops)
{
    int ret;
    byte* stored = NULL;
    int storedLen = 0;
    WP11_StatefulRec mem;
    WP11_StatefulRec disk;

    ret = wp11_Stateful_ReadStored(storeType, (int)o->slot->id, objId,
        &stored, &storedLen);
    if (ret == 0)
        ret = wp11_Stateful_Parse(o->keyData, (word32)o->keyDataLen, &mem);
    if (ret == 0)
        ret = wp11_Stateful_Parse(stored, (word32)storedLen, &disk);
    /* Another key's record at this id: the stored layout moved. */
    if (ret == 0 && !wp11_Stateful_SameKey(&mem, &disk))
        ret = BAD_STATE_E;
    if (ret == 0 && (disk.count < o->statefulSigCount ||
            disk.count < mem.count)) {
        ret = BAD_STATE_E;
    }
    if (ret == 0 && (force || disk.count != o->statefulSigCount ||
            storedLen != o->keyDataLen ||
            XMEMCMP(stored, o->keyData, (size_t)storedLen) != 0)) {
        ret = ops->load(o, stored, (word32)storedLen, 1);
    }
    XFREE(stored, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

static WP11_Object* wp11_Token_ObjectAt(WP11_Token* token, int id)
{
    WP11_Object* curr = token->object;
    int i;

    for (i = token->objCnt - 1; curr != NULL && i > id; i--)
        curr = curr->next;
    return (i == id) ? curr : NULL;
}

/* Take over the record at the id o was last stored at when it is further on
 * than memory, so a store pass never writes an older state. */
static int wp11_Stateful_Adopt(WP11_Object* o, int storeType, int tokenId,
    int* adopted)
{
    int ret;
    byte* stored = NULL;
    int storedLen = 0;
    WP11_StatefulRec mem;
    WP11_StatefulRec disk;
    WP11_Object* owner;

    *adopted = 0;
    if (o->statefulHomeId <= 0 ||
            wp11_Stateful_Parse(o->keyData, (word32)o->keyDataLen, &mem) != 0) {
        return 0;
    }
    /* Without a batch another key may already have written over the record. */
    owner = wp11_Token_ObjectAt(&o->slot->token, o->statefulHomeId - 1);
    if (!wp11_storage_atomic() && owner != NULL && owner != o &&
            wp11_Stateful_IsKey(owner)) {
        return 0;
    }
    /* The record must be there: without it a newer state may be missed. */
    ret = wp11_Stateful_ReadStored(storeType, tokenId, o->statefulHomeId - 1,
        &stored, &storedLen);
    if (ret == 0)
        ret = wp11_Stateful_Parse(stored, (word32)storedLen, &disk);
    if (ret == 0 && !wp11_Stateful_SameKey(&mem, &disk))
        ret = BAD_STATE_E;
    if (ret == 0 && disk.count > mem.count) {
        XFREE(o->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        o->keyData = stored;
        o->keyDataLen = storedLen;
        stored = NULL;
        *adopted = 1;
    }
    XFREE(stored, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Re-seal o's key data to its policy and the token key, from the token key
 * a store pass is replacing when there is one. */
static int wp11_Stateful_ReSealTo(WP11_Object* o)
{
    int ret;
    byte policy[WC_SHA256_DIGEST_SIZE];
    byte* rec = NULL;
    word32 recLen = 0;
    const byte* from = o->slot->token.key;

    if (o->slot->token.reKeyOld != NULL)
        from = o->slot->token.reKeyOld;
    ret = wp11_Stateful_Policy(o, policy);
    if (ret == 0) {
        ret = wp11_Stateful_ReSeal(o, o->keyData, (word32)o->keyDataLen,
            from, o->slot->token.key, policy, sizeof(policy), &rec, &recLen);
    }
    if (ret == 0) {
        XFREE(o->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        o->keyData = rec;
        o->keyDataLen = (int)recLen;
    }
    return ret;
}

/* Write a record that holds no state at id, in the current store pass. */
static int wp11_Stateful_WriteDead(int storeType, int tokenId, int id)
{
    int ret;
    void* storage = NULL;
    byte dead[12];

    XMEMSET(dead, 0, sizeof(dead));
    ret = wp11_storage_open(storeType, (CK_ULONG)tokenId, (CK_ULONG)id,
        (int)sizeof(dead), &storage);
    if (ret == 0) {
        ret = wp11_storage_write_array(storage, dead, sizeof(dead));
        ret = wp11_storage_close_write(storage, ret);
    }
    return ret;
}

/* Leave no state at objId for a key with no record to write there. */
static int wp11_Stateful_ClearAt(WP11_Object* o, int tokenId, int objId)
{
    int ret = 0;

    if (!wp11_storage_atomic()) {
        ret = wp11_storage_remove(wp11_Stateful_StoreType(o),
            (CK_ULONG)tokenId, (CK_ULONG)objId);
        if (ret == NOT_AVAILABLE_E)
            ret = 0;
        if (ret == 0)
            o->statefulHomeId = objId + 1;
    }
    else {
        ret = wp11_Stateful_WriteDead(wp11_Stateful_StoreType(o), tokenId,
            objId);
        if (ret == 0)
            o->statefulHomeNext = objId + 1;
    }
    return ret;
}

/* Overwrite the record a moved key left at oldId in the same store pass, so
 * no process signs from that copy. */
static int wp11_Stateful_Retire(WP11_Object* o, int storeType, int tokenId,
    int oldId)
{
    int ret = 0;
    byte* stored = NULL;
    int storedLen = 0;
    WP11_StatefulRec mem;
    WP11_StatefulRec disk;
    WP11_Object* owner;

    owner = wp11_Token_ObjectAt(&o->slot->token, oldId);
    /* A key now at oldId writes or removes the record there itself. */
    if ((owner != NULL && wp11_Stateful_IsKey(owner)) ||
            wp11_Stateful_Parse(o->keyData, (word32)o->keyDataLen, &mem) != 0) {
        return 0;
    }
    ret = wp11_Stateful_ReadStored(storeType, tokenId, oldId, &stored,
        &storedLen);
    if (ret == NOT_AVAILABLE_E)
        return 0;
    if (ret == 0 &&
            wp11_Stateful_Parse(stored, (word32)storedLen, &disk) == 0 &&
            wp11_Stateful_SameKey(&mem, &disk)) {
        ret = wp11_Stateful_WriteDead(storeType, tokenId, oldId);
    }
    XFREE(stored, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Records written by a store pass become the keys' last ones once it
 * commits. */
void wp11_Stateful_StoreDone(WP11_Token* token, int committed)
{
    WP11_Object* o;

    for (o = token->object; o != NULL; o = o->next) {
        if (committed && o->statefulHomeNext > 0) {
            o->statefulHomeId = o->statefulHomeNext;
            o->statefulResealed = 0;
        }
        o->statefulHomeNext = 0;
    }
}

int wp11_Stateful_IsKey(WP11_Object* object)
{
    if (object->objClass != CKO_PRIVATE_KEY)
        return 0;
#ifdef WOLFPKCS11_LMS_PRIVATE
    if (object->type == CKK_HSS)
        return 1;
#endif
    return 0;
}

int wp11_Stateful_ReKey(WP11_Object* object, const byte* oldKey,
    const byte* newKey, byte** keyData)
{
    int ret;
    int adopted = 0;
    int pending = object->statefulResealed;
    WP11_StatefulRec r;
    word32 len = 0;
    byte policy[WC_SHA256_DIGEST_SIZE];

    *keyData = NULL;
    ret = wp11_Stateful_Adopt(object, wp11_Stateful_StoreType(object),
        (int)object->slot->id, &adopted);
    /* A damaged record stays as it is and its key does not sign. */
    if (ret != 0)
        return wp11_Stateful_Damaged(ret) ? 0 : ret;
    if (wp11_Stateful_Parse(object->keyData, (word32)object->keyDataLen,
            &r) != 0 || r.kind != WP11_STATEFUL_KIND_SEALED) {
        return 0;
    }
    /* The record keeps its own policy digest, so a changed one stays refused,
     * unless it replaced one that was re-sealed to the key's policy. */
    if (adopted && pending) {
        ret = wp11_Stateful_Policy(object, policy);
        if (ret == 0) {
            ret = wp11_Stateful_ReSeal(object, object->keyData,
                (word32)object->keyDataLen, oldKey, newKey, policy,
                sizeof(policy), keyData, &len);
        }
    }
    else {
        ret = wp11_Stateful_ReSeal(object, object->keyData,
            (word32)object->keyDataLen, oldKey, newKey, NULL, 0, keyData,
            &len);
    }
    if (ret == 0 && len != (word32)object->keyDataLen) {
        XFREE(*keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *keyData = NULL;
        ret = BAD_STATE_E;
    }
    if (ret == 0)
        object->statefulResealed = 1;
    return ret;
}

/* Keygen's state is kept in memory until adding the key stores it; a later
 * state is stored durably before its signature is released. */
static int wp11_Stateful_SaveState(WP11_Object* o, const byte* priv,
    word32 privSz)
{
    int ret;
    WP11_StatefulRec r;
    byte* rec = NULL;
    word32 recLen = 0;

    if (o == NULL || priv == NULL || privSz == 0 ||
            privSz > WP11_STATEFUL_PRIV_MAX) {
        return BAD_FUNC_ARG;
    }
    if (o->statefulStoreId == 0) {
        rec = (byte*)XMALLOC(privSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (rec == NULL)
            return MEMORY_E;
        XMEMCPY(rec, priv, privSz);
        if (o->statefulBuf != NULL) {
            wc_ForceZero(o->statefulBuf, o->statefulBufLen);
            XFREE(o->statefulBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        o->statefulBuf = rec;
        o->statefulBufLen = privSz;
        return 0;
    }

    ret = wp11_Stateful_Parse(o->keyData, (word32)o->keyDataLen, &r);
    if (ret == 0) {
        ret = wp11_Stateful_Seal(o, r.shell, r.shellLen, r.policy,
            r.policyLen, o->statefulSigCount, priv, privSz,
            o->slot->token.key, &rec, &recLen);
    }
    if (ret == 0) {
        ret = wp11_Stateful_Write(wp11_Stateful_StoreType(o),
            (int)o->slot->id, o->statefulStoreId - 1, rec, recLen);
    }
    if (ret == 0) {
        XFREE(o->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        o->keyData = rec;
        o->keyDataLen = (int)recLen;
        o->statefulHomeId = o->statefulStoreId;
        rec = NULL;
    }
    XFREE(rec, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Turn the state that keygen left in statefulBuf into the key record, or
 * rebind a sealed state to a changed policy. */
static int wp11_Stateful_Encode(WP11_Object* object,
    const WP11_StatefulOps* ops)
{
    int ret = 0;
    byte shell[WP11_STATEFUL_SHELL_BUF];
    word32 shellLen = sizeof(shell);
    byte policy[WC_SHA256_DIGEST_SIZE];
    byte* rec = NULL;
    word32 recLen = 0;
    int adopted = 0;

    if (object->statefulBuf != NULL) {
        ret = ops->shell(object, shell, &shellLen);
        if (ret == 0)
            ret = wp11_Stateful_Policy(object, policy);
        if (ret == 0) {
            ret = wp11_Stateful_Seal(object, shell, shellLen, policy,
                sizeof(policy), object->statefulSigCount, object->statefulBuf,
                object->statefulBufLen, object->slot->token.key, &rec,
                &recLen);
        }
        if (ret == 0) {
            wc_ForceZero(object->statefulBuf, object->statefulBufLen);
            XFREE(object->statefulBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            object->statefulBuf = NULL;
            object->statefulBufLen = 0;
        }
    }
    else if (object->keyData != NULL && object->unbound) {
        ret = wp11_Stateful_Adopt(object, wp11_Stateful_StoreType(object),
            (int)object->slot->id, &adopted);
        /* A damaged record cannot be re-sealed; its key does not sign. */
        if (wp11_Stateful_Damaged(ret)) {
            ret = 0;
        }
        else {
            if (ret == 0)
                ret = wp11_Stateful_ReSealTo(object);
            if (ret == 0)
                object->statefulResealed = 1;
        }
    }
    if (ret == 0 && rec != NULL) {
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = rec;
        object->keyDataLen = (int)recLen;
    }
    if (ret == 0)
        object->unbound = 0;
    /* The store pass reads NOT_AVAILABLE_E as storage turned off. */
    if (ret == NOT_AVAILABLE_E)
        ret = BAD_STATE_E;
    return ret;
}

static int wp11_Stateful_Load(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

    ret = wp11_storage_open_readonly(wp11_Stateful_StoreType(object), tokenId,
        objId, &storage);
    if (ret == 0) {
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        wp11_storage_close(storage);
    }
    object->statefulHomeId = objId + 1;
    /* A missing or short record leaves the key unable to sign. */
    if (ret == NOT_AVAILABLE_E || ret == BUFFER_E || ret == ASN_PARSE_E) {
        object->keyData = NULL;
        object->keyDataLen = 0;
        ret = 0;
    }
    return ret;
}

static int wp11_Stateful_Store(WP11_Object* object, int tokenId, int objId,
    const WP11_StatefulOps* ops)
{
    int ret = 0;
    void* storage = NULL;
    int storeType = wp11_Stateful_StoreType(object);
    int adopted = 0;
    int oldHome;
    byte* prev = NULL;
    int prevLen = 0;

    /* No record was loaded and there is no state to store. A record at a
     * new id belongs to a destroyed key. */
    if (object->keyData == NULL && object->statefulBuf == NULL) {
        if (object->statefulHomeId != objId + 1)
            ret = wp11_Stateful_ClearAt(object, tokenId, objId);
        return ret;
    }
    if (object->keyData == NULL)
        ret = wp11_Stateful_Encode(object, ops);
    if (ret == 0) {
        /* Kept so a failed re-seal of an adopted record stays pending. */
        if (object->statefulResealed && object->keyData != NULL) {
            prev = (byte*)XMALLOC((size_t)object->keyDataLen, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (prev == NULL)
                return MEMORY_E;
            XMEMCPY(prev, object->keyData, (size_t)object->keyDataLen);
            prevLen = object->keyDataLen;
        }
        ret = wp11_Stateful_Adopt(object, storeType, tokenId, &adopted);
        /* A damaged record has no state to re-seal and the key cannot sign. */
        if (wp11_Stateful_Damaged(ret)) {
            XFREE(prev, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            object->statefulResealed = 0;
            if (object->statefulHomeId == objId + 1)
                return 0;
            return wp11_Stateful_ClearAt(object, tokenId, objId);
        }
        /* A re-seal done outside this pass is redone on the newer state. */
        if (ret == 0 && adopted && object->statefulResealed) {
            ret = wp11_Stateful_ReSealTo(object);
            if (ret != 0 && prev != NULL) {
                XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                object->keyData = prev;
                object->keyDataLen = prevLen;
                prev = NULL;
            }
        }
        XFREE(prev, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (ret == 0)
        ret = wp11_storage_open(storeType, tokenId, objId,
            object->keyDataLen, &storage);
    if (ret == 0) {
        ret = wp11_storage_write_array(storage, object->keyData,
            object->keyDataLen);
        ret = wp11_storage_close_write(storage, ret);
    }
    if (ret == 0) {
        oldHome = object->statefulHomeId;
        /* Without a store batch the record is committed already. */
        if (!wp11_storage_atomic())
            object->statefulHomeId = objId + 1;
        if (oldHome > 0 && oldHome != objId + 1) {
            ret = wp11_Stateful_Retire(object, storeType, tokenId,
                oldHome - 1);
        }
        if (ret == 0)
            object->statefulHomeNext = objId + 1;
    }
    /* The store pass reads NOT_AVAILABLE_E as storage turned off. */
    if (ret == NOT_AVAILABLE_E)
        ret = BAD_STATE_E;
    return ret;
}

/* Errors that wolfSSL reports before it uses a leaf. */
static int wp11_Stateful_SignArgError(int ret)
{
    return ret == BAD_FUNC_ARG || ret == BUFFER_E;
}

/* Each signature is released only after the advanced state is durable; a
 * failure disables the key until the next signature reloads it. */
static int wp11_Stateful_Sign(const WP11_StatefulOps* ops, unsigned char* data,
    word32 dataLen, unsigned char* sig, word32* sigLen, WP11_Object* priv)
{
    int ret = 0;
    word32 outLen = 0;
    word64 prevCount;
    int objId = -1;
    word64 total;
    void* held = NULL;
    int stateLocked = 0;
    WP11_Token* token;

    if (priv == NULL || sig == NULL || sigLen == NULL || priv->lock == NULL ||
            dataLen > (word32)INT_MAX) {
        return BAD_FUNC_ARG;
    }
    token = &priv->slot->token;

    /* Other objects stay usable; the state lock orders signs of stateful
     * keys. */
    WP11_Lock_LockRO(priv->lock);
    /* Stored ids must match the object list before a state write by id. */
    if (token->storeDirty) {
        WP11_Lock_UnlockRO(priv->lock);
        WP11_Lock_LockRW(priv->lock);
        ret = wp11_Token_StoreIfDirty(priv->slot);
        WP11_Lock_UnlockRW(priv->lock);
        WP11_Lock_LockRO(priv->lock);
        if (ret == 0 && token->storeDirty)
            ret = BAD_STATE_E;
    }
    /* A key a logout scrubbed is not reloaded here. */
    if (ret == 0 && priv->encoded)
        ret = NOT_AVAILABLE_E;
    /* The record matches the policy only once a policy change is stored. */
    if (ret == 0 && priv->unbound)
        ret = NOT_AVAILABLE_E;
    if (ret == 0) {
        objId = wp11_Token_ObjectId(token, priv);
        if (objId < 0)
            ret = NOT_AVAILABLE_E;
    }
    if (ret == 0) {
        ret = wp11_Slot_StateLock(priv->slot, &held);
        stateLocked = (ret == 0);
    }
    if (ret == 0 && (priv->statefulState & WP11_STATEFUL_EXHAUSTED))
        ret = KEY_EXHAUSTED_E;
    if (ret == 0) {
        /* A key disabled by a failure reloads: a released signature's state
         * is always stored. */
        ret = wp11_Stateful_Refresh(priv, wp11_Stateful_StoreType(priv),
            objId, (priv->statefulState & WP11_STATEFUL_VALID) == 0 ||
            (priv->statefulState & WP11_STATEFUL_RELOAD) != 0, ops);
        if (ret != 0) {
            priv->statefulState &= (byte)~WP11_STATEFUL_VALID;
            if (ret != MEMORY_E && ret != READ_ONLY_E)
                ret = NOT_AVAILABLE_E;
        }
        else if (priv->statefulState & WP11_STATEFUL_EXHAUSTED)
            ret = KEY_EXHAUSTED_E;
        else if ((priv->statefulState & WP11_STATEFUL_VALID) == 0)
            ret = NOT_AVAILABLE_E;
    }
    /* A state write that cannot be committed would still use up a leaf. */
    if (ret == 0) {
        ret = wp11_storage_check_durable(wp11_Stateful_StoreType(priv),
            (CK_ULONG)priv->slot->id, (CK_ULONG)objId);
    }
    if (ret == 0) {
        prevCount = priv->statefulSigCount;
        priv->statefulSigCount = prevCount + 1;
        priv->statefulStoreId = objId + 1;
        outLen = *sigLen;
        ret = ops->sign(priv, sig, &outLen, data, dataLen);
        priv->statefulStoreId = 0;
        if (ret == 0) {
            *sigLen = outLen;
            if (ops->total(priv, &total) == 0 && total != 0 &&
                    priv->statefulSigCount >= total) {
                priv->statefulState |= WP11_STATEFUL_EXHAUSTED;
            }
        }
        else {
            if (ret == KEY_EXHAUSTED_E)
                priv->statefulState |= WP11_STATEFUL_EXHAUSTED;
            else if (!wp11_Stateful_SignArgError(ret) || ops->broken(priv))
                priv->statefulState &= (byte)~WP11_STATEFUL_VALID;
            if (outLen > 0)
                XMEMSET(sig, 0, outLen);
            priv->statefulSigCount = prevCount;
        }
    }
    if (stateLocked)
        wp11_Slot_StateUnlock(held);
    WP11_Lock_UnlockRO(priv->lock);
    return ret;
}

/* Signatures left, from the stored counter. */
static int wp11_Stateful_SigsLeft(const WP11_StatefulOps* ops,
    WP11_Object* key, word64* remaining)
{
    word64 used, total;

    *remaining = 0;
    if (key->statefulState & WP11_STATEFUL_EXHAUSTED)
        return 0;
    if ((key->statefulState & WP11_STATEFUL_VALID) == 0)
        return NOT_AVAILABLE_E;
    if (ops->total(key, &total) != 0)
        return BAD_FUNC_ARG;
    used = key->statefulSigCount;
    if (total == 0)
        *remaining = ~(word64)0;
    else if (used < total)
        *remaining = total - used;
    return 0;
}

/* CKA_KEYS_REMAINING of a private key, in the usual attribute form. */
static int wp11_Stateful_GetKeysRemaining(const WP11_StatefulOps* ops,
    WP11_Object* object, byte* data, CK_ULONG* len)
{
    word64 remaining = 0;
    CK_ULONG v;

    if (object->encoded)
        return NOT_AVAILABLE_E;
    if (wp11_Stateful_SigsLeft(ops, object, &remaining) != 0)
        return NOT_AVAILABLE_E;

    v = (CK_ULONG)remaining;
    if (remaining > (word64)v)
        v = (CK_ULONG)-1;
    if (data == NULL) {
        *len = sizeof(v);
        return 0;
    }
    if (*len < sizeof(v)) {
        *len = sizeof(v);
        return BUFFER_E;
    }
    XMEMCPY(data, &v, sizeof(v));
    *len = sizeof(v);
    return 0;
}

/* Whether a pass committed the key's record. */
int WP11_Stateful_IsStored(WP11_Object* key)
{
    int stored;

    if (key->lock == NULL)
        return 0;
    WP11_Lock_LockRO(key->lock);
    WP11_Lock_LockRO(&key->slot->storeLock);
    stored = key->statefulHomeId > 0;
    WP11_Lock_UnlockRO(&key->slot->storeLock);
    WP11_Lock_UnlockRO(key->lock);
    return stored;
}
#endif /* WOLFPKCS11_STATEFUL_SIG_PRIVATE */

#ifdef WOLFPKCS11_LMS
/* LMS/HSS (RFC 8554). Keygen and signing need WOLFPKCS11_LMS_PRIVATE. */

/* Map tree height -> RFC 8554 LMS typecode. Returns 0 on unknown height. */
static CK_LMS_TYPE wp11_HssHeightToLmsType(int h)
{
    switch (h) {
        case 5:  return CKL_LMS_SHA256_M32_H5;
        case 10: return CKL_LMS_SHA256_M32_H10;
        case 15: return CKL_LMS_SHA256_M32_H15;
        case 20: return CKL_LMS_SHA256_M32_H20;
        case 25: return CKL_LMS_SHA256_M32_H25;
        default: return 0;
    }
}

/* Map Winternitz -> LMOTS typecode. Returns 0 on unknown. */
static CK_LMOTS_TYPE wp11_HssWToLmotsType(int w)
{
    switch (w) {
        case 1: return CKL_LMOTS_SHA256_N32_W1;
        case 2: return CKL_LMOTS_SHA256_N32_W2;
        case 4: return CKL_LMOTS_SHA256_N32_W4;
        case 8: return CKL_LMOTS_SHA256_N32_W8;
        default: return 0;
    }
}

#ifdef WOLFPKCS11_LMS_PRIVATE
/* RFC 8554 typecode to tree height or Winternitz width; 0 when unknown. */
static int wp11_HssLmsTypeToHeight(CK_LMS_TYPE t)
{
    switch (t) {
        case CKL_LMS_SHA256_M32_H5:  return 5;
        case CKL_LMS_SHA256_M32_H10: return 10;
        case CKL_LMS_SHA256_M32_H15: return 15;
        case CKL_LMS_SHA256_M32_H20: return 20;
        case CKL_LMS_SHA256_M32_H25: return 25;
        default:                     return 0;
    }
}

static int wp11_HssLmotsTypeToW(CK_LMOTS_TYPE t)
{
    switch (t) {
        case CKL_LMOTS_SHA256_N32_W1: return 1;
        case CKL_LMOTS_SHA256_N32_W2: return 2;
        case CKL_LMOTS_SHA256_N32_W4: return 4;
        case CKL_LMOTS_SHA256_N32_W8: return 8;
        default:                      return 0;
    }
}

/* HSS private-key shell: magic, version, levels, height, winternitz and the
 * public-key length as big-endian u32s, then the public key. */
#define WP11_HSS_SHELL_MAGIC      0x48535350UL  /* "HSSP" */
#define WP11_HSS_SHELL_VERSION    1U
#define WP11_HSS_SHELL_HDR_LEN    (6 * 4)
#define WP11_HSS_SHELL_MAX_LEN    (WP11_HSS_SHELL_HDR_LEN + \
                                   HSS_MAX_PUBLIC_KEY_LEN)

static int wp11_HssPackShellHeader(byte* out, word32 outLen, int levels,
    int height, int winternitz, const byte* pub, word32 pubLen)
{
    word32 needed = WP11_HSS_SHELL_HDR_LEN + pubLen;
    word32 idx = 0;

    if (out == NULL || outLen < needed)
        return BUFFER_E;
    wp11_Stateful_WriteU32(out + idx, (word32)WP11_HSS_SHELL_MAGIC);   idx += 4;
    wp11_Stateful_WriteU32(out + idx, (word32)WP11_HSS_SHELL_VERSION); idx += 4;
    wp11_Stateful_WriteU32(out + idx, (word32)levels);      idx += 4;
    wp11_Stateful_WriteU32(out + idx, (word32)height);      idx += 4;
    wp11_Stateful_WriteU32(out + idx, (word32)winternitz);  idx += 4;
    wp11_Stateful_WriteU32(out + idx, pubLen);              idx += 4;
    if (pub != NULL && pubLen > 0)
        XMEMCPY(out + idx, pub, pubLen);
    idx += pubLen;
    return (int)idx;
}

/* On success *pub points into in. */
static int wp11_HssParseShellHeader(const byte* in, word32 inLen,
    int* levels, int* height, int* winternitz,
    const byte** pub, word32* pubLen)
{
    word32 idx = 0;
    word32 magic, version, pl;
    word32 l, h, w;

    if (in == NULL || inLen < WP11_HSS_SHELL_HDR_LEN)
        return BAD_FUNC_ARG;
    magic = wp11_HbsReadU32(in + idx);   idx += 4;
    version = wp11_HbsReadU32(in + idx); idx += 4;
    if (magic != WP11_HSS_SHELL_MAGIC || version != WP11_HSS_SHELL_VERSION)
        return BAD_FUNC_ARG;
    l = wp11_HbsReadU32(in + idx);  idx += 4;
    h = wp11_HbsReadU32(in + idx);  idx += 4;
    w = wp11_HbsReadU32(in + idx);  idx += 4;
    pl = wp11_HbsReadU32(in + idx); idx += 4;
    if (pl > HSS_MAX_PUBLIC_KEY_LEN || idx + pl != inLen)
        return BAD_FUNC_ARG;
    *levels = (int)l;
    *height = (int)h;
    *winternitz = (int)w;
    *pub = in + idx;
    *pubLen = pl;
    return 0;
}

/* Build the shell of a key from its parameters and public key. */
static int wp11_Hss_Shell(WP11_Object* o, byte* shell, word32* shellLen)
{
    int ret;
    int levels = 0, height = 0, winternitz = 0;
    byte pub[HSS_MAX_PUBLIC_KEY_LEN];
    word32 pubLen = sizeof(pub);
    LmsKey* key = o->data.lmsKey;

    ret = wc_LmsKey_GetParameters(key, &levels, &height, &winternitz);
    if (ret == 0)
        ret = wc_LmsKey_ExportPubRaw(key, pub, &pubLen);
    if (ret == 0) {
        ret = wp11_HssPackShellHeader(shell, *shellLen, levels, height,
            winternitz, pub, pubLen);
        if (ret > 0) {
            *shellLen = (word32)ret;
            ret = 0;
        }
    }
    return ret;
}

/* Signatures a key can make, or 0 when that does not fit 64 bits. */
static word64 wp11_Hss_Total(int levels, int height)
{
    int totalH = levels * height;

    if (totalH <= 0 || totalH >= 64)
        return 0;
    return ((word64)1) << totalH;
}

static int wp11_Hss_ReadState_Cb(byte* priv, word32 privSz, void* ctx)
{
    WP11_Object* o = (WP11_Object*)ctx;

    if (o == NULL || priv == NULL || o->statefulBuf == NULL ||
            o->statefulBufLen != privSz) {
        return WC_LMS_RC_READ_FAIL;
    }
    XMEMCPY(priv, o->statefulBuf, privSz);
    return WC_LMS_RC_READ_TO_MEMORY;
}

/* wolfSSL releases a signature only when this returns
 * WC_LMS_RC_SAVED_TO_NV_MEMORY. */
static int wp11_Hss_WriteState_Cb(const byte* priv, word32 privSz, void* ctx)
{
    int ret = wp11_Stateful_SaveState((WP11_Object*)ctx, priv, privSz);

    if (ret == BAD_FUNC_ARG)
        return WC_LMS_RC_BAD_ARG;
    return (ret == 0) ? WC_LMS_RC_SAVED_TO_NV_MEMORY : WC_LMS_RC_WRITE_FAIL;
}

/* Load the key and its state from a record, adopting the record as the key
 * data. A key whose state does not load stays usable for attributes only. */
static int wp11_Hss_LoadState(WP11_Object* o, const byte* rec, word32 len,
    int reload)
{
    int ret;
    WP11_StatefulRec r;
    int levels = 0, height = 0, winternitz = 0;
    const byte* pub = NULL;
    word32 pubLen = 0;
    byte policy[WC_SHA256_DIGEST_SIZE];
    byte* priv = NULL;
    word32 privLen = 0;
    byte* copy = NULL;
    word64 total;
    LmsKey* key = o->data.lmsKey;

    ret = wp11_Stateful_Parse(rec, len, &r);
    if (ret == 0) {
        ret = wp11_HssParseShellHeader(r.shell, r.shellLen, &levels, &height,
            &winternitz, &pub, &pubLen);
    }
    if (ret == 0 && rec != o->keyData) {
        copy = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (copy == NULL)
            ret = MEMORY_E;
        else
            XMEMCPY(copy, rec, len);
    }
    if (ret != 0) {
        /* Decoded but unable to sign, as for a record that does not load. */
        if (!o->encoded)
            wc_LmsKey_Free(key);
        else
            o->encoded = 0;
        o->statefulState = 0;
        if (wc_LmsKey_Init(key, NULL, INVALID_DEVID) == 0 && levels != 0)
            (void)wc_LmsKey_SetParameters(key, levels, height, winternitz);
        return ret;
    }

    /* encoded is read without storeLock, so it is only written to change. */
    if (!o->encoded)
        wc_LmsKey_Free(key);
    else
        o->encoded = 0;
    o->statefulState = 0;
    if (r.kind != WP11_STATEFUL_KIND_SEALED) {
        ret = NOT_COMPILED_IN;
    }
    else {
        /* Software only: with a device id wc_LmsKey_Reload skips the read
         * callback and leaves the key without its private state. */
        ret = wc_LmsKey_Init(key, NULL, INVALID_DEVID);
        if (ret == 0)
            ret = wc_LmsKey_SetParameters(key, levels, height, winternitz);
        if (ret == 0)
            ret = wp11_Stateful_Policy(o, policy);
        if (ret == 0) {
            if (r.policyLen != sizeof(policy) ||
                    XMEMCMP(r.policy, policy, sizeof(policy)) != 0) {
                ret = AES_GCM_AUTH_E;
            }
        }
        if (ret == 0) {
            privLen = r.ctLen - AES_BLOCK_SIZE;
            priv = (byte*)XMALLOC(privLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (priv == NULL)
                ret = MEMORY_E;
        }
        if (ret == 0)
            ret = wp11_Stateful_Unseal(o, &r, o->slot->token.key, priv);
        if (ret == 0) {
            o->statefulSigCount = r.count;
            total = wp11_Hss_Total(levels, height);
            if (total != 0 && r.count >= total) {
                o->statefulState |= WP11_STATEFUL_EXHAUSTED;
            }
            else if (!reload) {
                /* Rebuilding the trees waits for the first signature. */
                o->statefulState |= WP11_STATEFUL_RELOAD;
            }
            else {
                ret = wc_LmsKey_SetWriteCb(key, wp11_Hss_WriteState_Cb);
                if (ret == 0)
                    ret = wc_LmsKey_SetReadCb(key, wp11_Hss_ReadState_Cb);
                if (ret == 0)
                    ret = wc_LmsKey_SetContext(key, o);
                if (ret == 0) {
                    o->statefulBuf = priv;
                    o->statefulBufLen = privLen;
                    ret = wc_LmsKey_Reload(key);
                    o->statefulBuf = NULL;
                    o->statefulBufLen = 0;
                }
            }
        }
    }
    if (ret == 0 && (o->statefulState & WP11_STATEFUL_EXHAUSTED) == 0)
        o->statefulState |= WP11_STATEFUL_VALID;
    if (ret != 0) {
        /* Keep the parameters so the key still reports its attributes. */
        wc_LmsKey_Free(key);
        if (wc_LmsKey_Init(key, NULL, INVALID_DEVID) == 0)
            (void)wc_LmsKey_SetParameters(key, levels, height, winternitz);
    }
    if (priv != NULL) {
        wc_ForceZero(priv, privLen);
        XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (copy != NULL) {
        if (ret == 0) {
            XFREE(o->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            o->keyData = copy;
            o->keyDataLen = (int)len;
        }
        else {
            XFREE(copy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
    return ret;
}

static int wp11_Hss_SignKey(WP11_Object* o, byte* sig, word32* sigLen,
    const byte* msg, word32 msgLen)
{
    return wc_LmsKey_Sign(o->data.lmsKey, sig, sigLen, msg, (int)msgLen);
}

static int wp11_Hss_TotalOf(WP11_Object* o, word64* total)
{
    int ret;
    int levels = 0, height = 0, winternitz = 0;

    ret = wc_LmsKey_GetParameters(o->data.lmsKey, &levels, &height,
        &winternitz);
    if (ret == 0)
        *total = wp11_Hss_Total(levels, height);
    return ret;
}

static int wp11_Hss_Broken(WP11_Object* o)
{
    return o->data.lmsKey->state == WC_LMS_STATE_BAD;
}

static const WP11_StatefulOps wp11_HssOps = {
    wp11_Hss_Shell, wp11_Hss_LoadState, wp11_Hss_SignKey, wp11_Hss_TotalOf,
    wp11_Hss_Broken
};
#endif /* WOLFPKCS11_LMS_PRIVATE */

/* Import a raw HSS public key into the given wolfSSL LmsKey. wolfSSL derives
 * the parameter set from the key bytes (RFC 8554 self-describing public key),
 * so no parameters need to be set first. On failure the (partially
 * initialized) key is NOT freed here; the caller owns it. */
static int wp11_HssImportPub(LmsKey* key, int devId, const byte* pub,
    word32 pubLen)
{
    int ret;

    ret = wc_LmsKey_Init(key, NULL, devId);
    if (ret == 0)
        ret = wc_LmsKey_ImportPubRaw(key, pub, pubLen);
    return ret;
}

/* Validate caller-supplied HSS parameter attributes against the parameters
 * wolfSSL derived from the just-imported public key. Per the PKCS#11 v3.3 HSS
 * profile the public-key parameters are the individual CK_ULONG attributes
 * CKA_HSS_LEVELS, CKA_HSS_LMS_TYPE (top-level tree height encoding) and
 * CKA_HSS_LMOTS_TYPE (Winternitz encoding). Each is optional; a supplied value
 * that does not match the key is rejected with BAD_FUNC_ARG. levelsAttr,
 * lmsAttr and lmotsAttr are the raw attribute buffers (NULL when absent) with
 * lengths levelsLen/lmsLen/lmotsLen. */
static int wp11_HssCheckParamAttrs(LmsKey* key,
    const byte* levelsAttr, word32 levelsLen,
    const byte* lmsAttr, word32 lmsLen,
    const byte* lmotsAttr, word32 lmotsLen)
{
    int ret, levels = 0, height = 0, winternitz = 0;
    CK_ULONG v;

    ret = wc_LmsKey_GetParameters(key, &levels, &height, &winternitz);
    if (ret != 0)
        return ret;
    if (levelsAttr != NULL) {
        if (levelsLen != sizeof(v))
            return BAD_FUNC_ARG;
        XMEMCPY(&v, levelsAttr, sizeof(v));
        if (v != (CK_ULONG)levels)
            return BAD_FUNC_ARG;
    }
    if (lmsAttr != NULL) {
        if (lmsLen != sizeof(v))
            return BAD_FUNC_ARG;
        XMEMCPY(&v, lmsAttr, sizeof(v));
        if (v != (CK_ULONG)wp11_HssHeightToLmsType(height))
            return BAD_FUNC_ARG;
    }
    if (lmotsAttr != NULL) {
        if (lmotsLen != sizeof(v))
            return BAD_FUNC_ARG;
        XMEMCPY(&v, lmotsAttr, sizeof(v));
        if (v != (CK_ULONG)wp11_HssWToLmotsType(winternitz))
            return BAD_FUNC_ARG;
    }
    return 0;
}

#ifndef WOLFPKCS11_NO_STORE
/* Serialize the public key: keyData holds the raw RFC 8554 HSS public key. */
int wp11_Object_Encode_HssKey(WP11_Object* object)
{
    int ret;
    word32 pubLen = 0;
    unsigned char* oldData = object->keyData;
    int oldLen = object->keyDataLen;

    if (object->objClass == CKO_PUBLIC_KEY) {
        ret = wc_LmsKey_GetPubLen(object->data.lmsKey, &pubLen);
        if (ret == 0) {
            object->keyData = (unsigned char*)XMALLOC(pubLen, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (object->keyData == NULL)
                ret = MEMORY_E;
        }
        if (ret == 0) {
            ret = wc_LmsKey_ExportPubRaw(object->data.lmsKey, object->keyData,
                &pubLen);
            if (ret == 0)
                object->keyDataLen = (int)pubLen;
        }
        wp11_Object_EncodeDone(object, oldData, oldLen, pubLen, ret);
        return ret;
    }
#ifdef WOLFPKCS11_LMS_PRIVATE
    if (object->objClass == CKO_PRIVATE_KEY)
        return wp11_Stateful_Encode(object, &wp11_HssOps);
#endif
    return NOT_AVAILABLE_E;
}

int wp11_Object_Decode_HssKey(WP11_Object* object)
{
    int ret;

    /* A key decoded before, e.g. at an earlier login, holds allocations that
     * re-initialising it would leak. */
    if (!object->encoded && object->objClass == CKO_PUBLIC_KEY)
        wc_LmsKey_Free(object->data.lmsKey);

    if (object->objClass == CKO_PUBLIC_KEY) {
        /* Raw RFC 8554 public key; wolfSSL re-derives the parameter set. */
        ret = wp11_HssImportPub(object->data.lmsKey, object->devId,
            object->keyData, (word32)object->keyDataLen);
        /* The import helper never frees the key; WP11_Object_Free does. */
        object->encoded = 0;
        return ret;
    }
#ifdef WOLFPKCS11_LMS_PRIVATE
    if (object->objClass == CKO_PRIVATE_KEY) {
        /* A key whose record or state does not load stays visible, so it can
         * be destroyed, but does not sign. */
        (void)wp11_Hss_LoadState(object, object->keyData,
            (word32)object->keyDataLen, 0);
        return 0;
    }
#endif
    return NOT_AVAILABLE_E;
}

int wp11_Object_Load_HssKey(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

#ifdef WOLFPKCS11_LMS_PRIVATE
    if (object->objClass == CKO_PRIVATE_KEY)
        return wp11_Stateful_Load(object, tokenId, objId);
#endif
    ret = wp11_storage_open_readonly(WOLFPKCS11_STORE_HSSKEY_PUB, tokenId,
        objId, &storage);
    if (ret == 0) {
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        wp11_storage_close(storage);
    }
    return ret;
}

int wp11_Object_Store_HssKey(WP11_Object* object, int tokenId, int objId)
{
    int ret = 0;
    void* storage = NULL;

#ifdef WOLFPKCS11_LMS_PRIVATE
    if (object->objClass == CKO_PRIVATE_KEY)
        return wp11_Stateful_Store(object, tokenId, objId, &wp11_HssOps);
#endif
    if (object->keyData == NULL)
        ret = wp11_Object_Encode_HssKey(object);
    if (ret == 0)
        ret = wp11_storage_open(WOLFPKCS11_STORE_HSSKEY_PUB, tokenId, objId,
            object->keyDataLen, &storage);
    if (ret == 0) {
        ret = wp11_storage_write_array(storage, object->keyData,
            object->keyDataLen);
        ret = wp11_storage_close_write(storage, ret);
    }
    return ret;
}

#endif /* !WOLFPKCS11_NO_STORE */

/* Import an HSS public key from a C_CreateObject template. Following the
 * PKCS#11 v3.3 HSS profile the collected attributes are data[0]=CKA_HSS_LEVELS,
 * data[1]=CKA_HSS_LMS_TYPE, data[2]=CKA_HSS_LMOTS_TYPE (all optional CK_ULONG)
 * and data[3]=CKA_VALUE, the raw RFC 8554 public key. wolfSSL derives the
 * parameter set from the key bytes; any supplied CKA_HSS_* attribute is
 * validated against the derived parameters and a mismatch is rejected.
 * Private-key import is rejected. */
int WP11_Object_SetHssKey(WP11_Object* object, unsigned char** data,
                          CK_ULONG* len)
{
    int ret = 0;
    LmsKey* newKey = NULL;

    if (object == NULL || data == NULL || len == NULL)
        return BAD_FUNC_ARG;
#ifdef WOLFPKCS11_LMS_PRIVATE
    /* Keygen fills in a private key created without a value. */
    if (object->objClass == CKO_PRIVATE_KEY) {
        if (data[3] != NULL)
            return BAD_FUNC_ARG;
        return 0;
    }
    if (object->objClass != CKO_PUBLIC_KEY)
        return BAD_FUNC_ARG;
    if (data[3] == NULL)
        return 0;
#else
    if (object->objClass != CKO_PUBLIC_KEY)
        return BAD_FUNC_ARG;
    /* A public key must carry its value. There is no keygen path in a
     * verify-only build that would populate it later, so an absent
     * CKA_VALUE is an incomplete template rather than a deferred import;
     * reject it instead of creating an unusable object. */
    if (data[3] == NULL)
        return BAD_FUNC_ARG;
#endif

    if (object->lock != NULL)
        WP11_Lock_LockRW(object->lock);

    /* Import into a temporary key and swap it in only after it fully validates,
     * so a failed re-import (C_SetAttributeValue with a new CKA_VALUE) leaves
     * the existing key unchanged as PKCS#11 requires. */
    newKey = (LmsKey*)XMALLOC(sizeof(LmsKey), NULL, DYNAMIC_TYPE_KEY);
    if (newKey == NULL)
        ret = MEMORY_E;
    if (ret == 0) {
        XMEMSET(newKey, 0, sizeof(LmsKey));
        ret = wp11_HssImportPub(newKey, object->devId, data[3],
            (word32)len[3]);
    }
    if (ret == 0) {
        ret = wp11_HssCheckParamAttrs(newKey, data[0], (word32)len[0],
            data[1], (word32)len[1], data[2], (word32)len[2]);
    }
    if (ret == 0) {
        /* Replace the live key and drop the cached serialization so a later
         * store re-encodes from the new key instead of persisting stale bytes. */
        if (object->data.lmsKey != NULL) {
        #ifndef WOLFPKCS11_NO_STORE
            if (!object->encoded)
        #endif
                wc_LmsKey_Free(object->data.lmsKey);
            XFREE(object->data.lmsKey, NULL, DYNAMIC_TYPE_KEY);
        }
        object->data.lmsKey = newKey;
        newKey = NULL;
    #ifndef WOLFPKCS11_NO_STORE
        object->encoded = 0;
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = NULL;
        object->keyDataLen = 0;
    #endif
    }
    if (newKey != NULL) {
        wc_LmsKey_Free(newKey);
        XFREE(newKey, NULL, DYNAMIC_TYPE_KEY);
    }

    if (object->lock != NULL)
        WP11_Lock_UnlockRW(object->lock);
    return ret;
}

/**
 * Return the length of an HSS signature in bytes.
 *
 * @param  key  [in]  HSS public or private key object.
 * @return  Length of HSS signature in bytes, 0 when it cannot be determined.
 */
word32 WP11_Hss_SigLen(WP11_Object* key)
{
    word32 len = 0;

    if (key->lock != NULL)
        WP11_Lock_LockRO(key->lock);
#ifdef WOLFPKCS11_LMS_PRIVATE
    if (key->objClass == CKO_PRIVATE_KEY)
        WP11_Lock_LockRO(&key->slot->storeLock);
#endif
    if (key->data.lmsKey == NULL ||
            wc_LmsKey_GetSigLen(key->data.lmsKey, &len) != 0) {
        len = 0;
    }
#ifdef WOLFPKCS11_LMS_PRIVATE
    if (key->objClass == CKO_PRIVATE_KEY)
        WP11_Lock_UnlockRO(&key->slot->storeLock);
#endif
    if (key->lock != NULL)
        WP11_Lock_UnlockRO(key->lock);

    return len;
}

/* Verify an HSS signature over a raw message. Stateless on the verifier. */
int WP11_Hss_Verify(unsigned char* sig, word32 sigLen, unsigned char* data,
                    word32 dataLen, int* stat, WP11_Object* pub)
{
    int ret;
    word32 expSigLen = 0;

    if (pub == NULL || pub->data.lmsKey == NULL || stat == NULL)
        return BAD_FUNC_ARG;

    /* wc_LmsKey_Verify only reads the key and keeps its LmsState local, so
     * concurrent verifies on one object can share the RO lock. */
    if (pub->lock != NULL)
        WP11_Lock_LockRO(pub->lock);

    if (wc_LmsKey_GetSigLen(pub->data.lmsKey, &expSigLen) == 0 &&
            sigLen != expSigLen) {
        *stat = 0;
        ret = 0;
    }
    else {
        /* Unlike XMSS, whose wolfSSL verify rejects a zero-length message with
         * BAD_FUNC_ARG, wc_LmsKey_Verify accepts an empty message, so HSS needs
         * no dataLen == 0 special-case here (see WP11_Xmss_Verify). */
        ret = wc_LmsKey_Verify(pub->data.lmsKey, sig, sigLen, data,
            (int)dataLen);
        /* Only a genuine verification mismatch (SIG_VERIFY_E) maps to stat=0.
         * Remaining argument/state errors surface as a function failure so
         * they are not silently reported as an invalid signature. */
        if (ret == 0) {
            *stat = 1;
        }
        else if (ret == SIG_VERIFY_E) {
            *stat = 0;
            ret = 0;
        }
        else {
            *stat = 0;
        }
    }

    if (pub->lock != NULL)
        WP11_Lock_UnlockRO(pub->lock);

    return ret;
}

#ifdef WOLFPKCS11_LMS_PRIVATE
/* Generate an HSS key pair. Adding the private key to the token stores its
 * first state. */
int WP11_Hss_GenerateKeyPair(WP11_Object* pub, WP11_Object* priv,
                             CK_ULONG levels, CK_LMS_TYPE lmsType,
                             CK_LMOTS_TYPE lmotsType, WP11_Slot* slot)
{
    int ret;
    int nLevels, height, winternitz;
    WC_RNG rng;
    byte pubBuf[HSS_MAX_PUBLIC_KEY_LEN];
    word32 pubLen = sizeof(pubBuf);
    LmsKey* key;

    if (pub == NULL || priv == NULL || slot == NULL ||
            pub->data.lmsKey == NULL || priv->data.lmsKey == NULL) {
        return BAD_FUNC_ARG;
    }
    key = priv->data.lmsKey;

    height = wp11_HssLmsTypeToHeight(lmsType);
    winternitz = wp11_HssLmotsTypeToW(lmotsType);
    if (levels < 1 || levels > (CK_ULONG)LMS_MAX_LEVELS || height == 0 ||
            winternitz == 0) {
        return BAD_FUNC_ARG;
    }
    nLevels = (int)levels;
    priv->statefulSigCount = 0;
    priv->statefulStoreId = 0;

    /* Software only, as in wp11_Hss_LoadState. */
    ret = wc_LmsKey_Init(key, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_LmsKey_SetParameters(key, nLevels, height, winternitz);
    if (ret == 0)
        ret = wc_LmsKey_SetWriteCb(key, wp11_Hss_WriteState_Cb);
    if (ret == 0)
        ret = wc_LmsKey_SetReadCb(key, wp11_Hss_ReadState_Cb);
    if (ret == 0)
        ret = wc_LmsKey_SetContext(key, priv);
    if (ret == 0)
        ret = wp11_Slot_NewRng(slot, &rng);
    if (ret == 0) {
        ret = wc_LmsKey_MakeKey(key, &rng);
        wc_FreeRng(&rng);
    }
    if (ret == 0 && priv->statefulBuf == NULL)
        ret = BAD_STATE_E;

    if (ret == 0)
        ret = wc_LmsKey_ExportPubRaw(key, pubBuf, &pubLen);
    if (ret == 0)
        ret = wc_LmsKey_Init(pub->data.lmsKey, NULL, pub->devId);
    if (ret == 0)
        ret = wc_LmsKey_SetParameters(pub->data.lmsKey, nLevels, height,
            winternitz);
    if (ret == 0)
        ret = wc_LmsKey_ImportPubRaw(pub->data.lmsKey, pubBuf, pubLen);

    if (ret == 0) {
        priv->local = pub->local = 1;
        priv->keyGenMech = pub->keyGenMech = CKM_HSS_KEY_PAIR_GEN;
        priv->statefulState |= WP11_STATEFUL_VALID;
        priv->opFlag |= WP11_FLAG_NOT_COPYABLE;
    }
    else {
        wc_LmsKey_Free(key);
        /* encoded stops WP11_Object_Free from freeing the key again. */
        priv->encoded = 1;
        priv->statefulState = 0;
        if (priv->statefulBuf != NULL) {
            wc_ForceZero(priv->statefulBuf, priv->statefulBufLen);
            XFREE(priv->statefulBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            priv->statefulBuf = NULL;
            priv->statefulBufLen = 0;
        }
    }

    wc_ForceZero(pubBuf, sizeof(pubBuf));
    return ret;
}

int WP11_Hss_Sign(unsigned char* data, word32 dataLen, unsigned char* sig,
                  word32* sigLen, WP11_Object* priv)
{
    if (priv == NULL || priv->data.lmsKey == NULL)
        return BAD_FUNC_ARG;
    return wp11_Stateful_Sign(&wp11_HssOps, data, dataLen, sig, sigLen, priv);
}
#endif /* WOLFPKCS11_LMS_PRIVATE */


/* Parameters of the key, from its record while the key is not loaded. */
static int wp11_HssGetParams(WP11_Object* object, int* levels, int* height,
    int* winternitz)
{
    int ret;
#ifdef WOLFPKCS11_LMS_PRIVATE
    WP11_StatefulRec r;
    const byte* pub = NULL;
    word32 pubLen = 0;
#endif

    ret = wc_LmsKey_GetParameters(object->data.lmsKey, levels, height,
        winternitz);
#ifdef WOLFPKCS11_LMS_PRIVATE
    if (ret != 0 && object->objClass == CKO_PRIVATE_KEY &&
            wp11_Stateful_Parse(object->keyData, (word32)object->keyDataLen,
                &r) == 0) {
        ret = wp11_HssParseShellHeader(r.shell, r.shellLen, levels, height,
            winternitz, &pub, &pubLen);
        if (ret == 0 && (*levels < 1 || *levels > LMS_MAX_LEVELS))
            ret = BAD_FUNC_ARG;
    }
#endif
    return ret;
}

/* Serve HSS-specific attributes from a public or private key object. */
int wp11_HssObject_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                           byte* data, CK_ULONG* len)
{
    int ret = 0;
    int levels = 0, height = 0, winternitz = 0;

    if (object == NULL || object->data.lmsKey == NULL || len == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFPKCS11_LMS_PRIVATE
    /* A sign reloading the key holds the store lock. */
    if (object->objClass == CKO_PRIVATE_KEY)
        WP11_Lock_LockRO(&object->slot->storeLock);
#endif
    switch (type) {
        case CKA_HSS_LEVELS: {
            CK_ULONG v;
            ret = wp11_HssGetParams(object, &levels, &height, &winternitz);
            if (ret == 0) {
                v = (CK_ULONG)levels;
                if (data == NULL)
                    *len = sizeof(v);
                else if (*len < sizeof(v)) {
                    *len = sizeof(v);
                    ret = BUFFER_E;
                }
                else {
                    XMEMCPY(data, &v, sizeof(v));
                    *len = sizeof(v);
                }
            }
            break;
        }
        case CKA_HSS_LMS_TYPE: {
            CK_LMS_TYPE v;
            ret = wp11_HssGetParams(object, &levels, &height, &winternitz);
            if (ret == 0) {
                v = wp11_HssHeightToLmsType(height);
                if (v == 0)
                    ret = NOT_AVAILABLE_E;
                else if (data == NULL)
                    *len = sizeof(v);
                else if (*len < sizeof(v)) {
                    *len = sizeof(v);
                    ret = BUFFER_E;
                }
                else {
                    XMEMCPY(data, &v, sizeof(v));
                    *len = sizeof(v);
                }
            }
            break;
        }
        case CKA_HSS_LMOTS_TYPE: {
            CK_LMOTS_TYPE v;
            ret = wp11_HssGetParams(object, &levels, &height, &winternitz);
            if (ret == 0) {
                v = wp11_HssWToLmotsType(winternitz);
                if (v == 0)
                    ret = NOT_AVAILABLE_E;
                else if (data == NULL)
                    *len = sizeof(v);
                else if (*len < sizeof(v)) {
                    *len = sizeof(v);
                    ret = BUFFER_E;
                }
                else {
                    XMEMCPY(data, &v, sizeof(v));
                    *len = sizeof(v);
                }
            }
            break;
        }
        case CKA_HSS_LMS_TYPES:
        case CKA_HSS_LMOTS_TYPES: {
            /* wolfSSL uses uniform LMS/LMOTS parameters across all HSS levels, so
             * every array entry is the top-level type. Per-level types (allowed
             * by the PKCS#11 v3.3 profile) are not expressible by wolfSSL and are
             * not supported here. */
            CK_ULONG total;
            CK_ULONG fill;
            int i;
            ret = wp11_HssGetParams(object, &levels, &height, &winternitz);
            if (ret == 0) {
                total = (CK_ULONG)(sizeof(CK_ULONG) * levels);
                fill = (type == CKA_HSS_LMS_TYPES)
                    ? wp11_HssHeightToLmsType(height)
                    : wp11_HssWToLmotsType(winternitz);
                if (fill == 0)
                    ret = NOT_AVAILABLE_E;
                else if (data == NULL)
                    *len = total;
                else if (*len < total) {
                    *len = total;
                    ret = BUFFER_E;
                }
                else {
                    for (i = 0; i < levels; i++)
                        XMEMCPY(data + i * sizeof(CK_ULONG), &fill,
                            sizeof(CK_ULONG));
                    *len = total;
                }
            }
            break;
        }
        case CKA_KEYS_REMAINING:
            /* Remaining-signature count is a private-key/state property. In a
             * verify-only build (or for a public key) it is unavailable. */
            ret = NOT_AVAILABLE_E;
#ifdef WOLFPKCS11_LMS_PRIVATE
            if (object->objClass == CKO_PRIVATE_KEY)
                ret = wp11_Stateful_GetKeysRemaining(&wp11_HssOps, object,
                    data, len);
#endif
            break;
        case CKA_VALUE:
            if (object->objClass == CKO_PUBLIC_KEY) {
                word32 pubLen = 0;
                ret = wc_LmsKey_GetPubLen(object->data.lmsKey, &pubLen);
                if (ret == 0) {
                    if (data == NULL)
                        *len = pubLen;
                    else if (*len < pubLen) {
                        *len = pubLen;
                        ret = BUFFER_E;
                    }
                    else {
                        ret = wc_LmsKey_ExportPubRaw(object->data.lmsKey,
                            data, &pubLen);
                        if (ret == 0)
                            *len = pubLen;
                    }
                }
            }
            else {
                *len = CK_UNAVAILABLE_INFORMATION;
                ret = NOT_AVAILABLE_E;
            }
            break;
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }
#ifdef WOLFPKCS11_LMS_PRIVATE
    if (object->objClass == CKO_PRIVATE_KEY)
        WP11_Lock_UnlockRO(&object->slot->storeLock);
#endif
    return ret;
}

/* Check a supplied CKA_HSS_LMS_TYPES or CKA_HSS_LMOTS_TYPES array: one entry
 * per level, each equal to the key type. Caller holds the object lock. */
int wp11_HssCheckTypesAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                           const byte* data, CK_ULONG len)
{
    int ret;
    int levels = 0;
    int height = 0;
    int winternitz = 0;
    int i;
    CK_ULONG expected;
    CK_ULONG entry;

    if (object->data.lmsKey == NULL || data == NULL)
        return BAD_FUNC_ARG;

    ret = wp11_HssGetParams(object, &levels, &height, &winternitz);
    if (ret != 0)
        return ret;

    expected = (type == CKA_HSS_LMS_TYPES)
        ? (CK_ULONG)wp11_HssHeightToLmsType(height)
        : (CK_ULONG)wp11_HssWToLmotsType(winternitz);
    if (expected == 0)
        return BAD_FUNC_ARG;
    if (len != (CK_ULONG)(sizeof(CK_ULONG) * levels))
        return BAD_FUNC_ARG;

    for (i = 0; i < levels; i++) {
        XMEMCPY(&entry, data + i * sizeof(CK_ULONG), sizeof(entry));
        if (entry != expected)
            return BAD_FUNC_ARG;
    }

    return 0;
}
#endif /* WOLFPKCS11_LMS */

#ifdef WOLFPKCS11_XMSS
/* ===========================================================================
 * XMSS/XMSS^MT (RFC 8391): verification and public-key import.
 *
 * Verify-only. One wolfSSL XmssKey type serves both XMSS and XMSS^MT; the
 * PKCS#11 key type (CKK_XMSS vs CKK_XMSSMT) selects which via the is_xmssmt
 * flag. The raw public key carries the parameter-set OID in its leading
 * bytes, so wc_XmssKey_ImportPubRaw_ex derives the parameter set on import.
 * A CKA_PARAMETER_SET attribute is optional and, when supplied, is validated
 * against the OID in the key.
 * ========================================================================= */

/* Length of the parameter-set OID prefix in a raw RFC 8391 public key. wolfSSL
 * only exposes XMSS_OID_LEN when built with WOLFSSL_HAVE_XMSS and it is absent
 * from some released headers, so define our own to keep the build independent
 * of the wolfSSL version. */
#define WP11_XMSS_OID_LEN 4

/* Import a raw XMSS/XMSS^MT public key into the given wolfSSL XmssKey, deriving
 * the parameter set from the embedded OID. is_xmssmt disambiguates the XMSS and
 * XMSS^MT OID namespaces (which overlap) and comes from the PKCS#11 key type.
 * When the caller supplies a CKA_PARAMETER_SET (params != NULL, the OID as a
 * CK_ULONG) it must match the OID in the public key. On failure the key is NOT
 * freed here; the caller owns it. */
static int wp11_XmssImportPub(XmssKey* key, int is_xmssmt, int devId,
    const byte* pub, word32 pubLen, const byte* params, word32 paramsLen)
{
    int ret;

    ret = wc_XmssKey_Init(key, NULL, devId);
    if (ret == 0 && params != NULL) {
        CK_ULONG userOid;
        if (paramsLen != sizeof(CK_ULONG) || pubLen < WP11_XMSS_OID_LEN) {
            ret = BAD_FUNC_ARG;
        }
        else {
            XMEMCPY(&userOid, params, sizeof(userOid));
            if (userOid != (CK_ULONG)wp11_HbsReadU32(pub))
                ret = BAD_FUNC_ARG;
        }
    }
    if (ret == 0)
        ret = wc_XmssKey_ImportPubRaw_ex(key, pub, pubLen, is_xmssmt);
    return ret;
}

#ifndef WOLFPKCS11_NO_STORE
/* Serialize the public key: keyData holds the raw RFC 8391 public key. */
int wp11_Object_Encode_XmssKey(WP11_Object* object)
{
    int ret;
    word32 pubLen = 0;
    unsigned char* oldData = object->keyData;
    int oldLen = object->keyDataLen;

    if (object->objClass != CKO_PUBLIC_KEY)
        return NOT_AVAILABLE_E;

    ret = wc_XmssKey_GetPubLen(object->data.xmssKey, &pubLen);
    if (ret == 0) {
        object->keyData = (unsigned char*)XMALLOC(pubLen, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (object->keyData == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0) {
        ret = wc_XmssKey_ExportPubRaw(object->data.xmssKey, object->keyData,
            &pubLen);
        if (ret == 0)
            object->keyDataLen = (int)pubLen;
    }
    wp11_Object_EncodeDone(object, oldData, oldLen, pubLen, ret);
    return ret;
}

int wp11_Object_Decode_XmssKey(WP11_Object* object)
{
    int ret;

    if (object->objClass != CKO_PUBLIC_KEY)
        return NOT_AVAILABLE_E;

    /* Reload from the stored raw public key; wolfSSL re-derives the parameter
     * set from the embedded OID (no separate parameter set is persisted). */
    ret = wp11_XmssImportPub(object->data.xmssKey,
        (object->type == CKK_XMSSMT) ? 1 : 0, object->devId, object->keyData,
        (word32)object->keyDataLen, NULL, 0);
    /* Object owns the key on all paths; encoded stays 0 for the single free in
     * WP11_Object_Free. See wp11_Object_Decode_HssKey. */
    object->encoded = 0;
    return ret;
}

int wp11_Object_Load_XmssKey(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

    ret = wp11_storage_open_readonly(WOLFPKCS11_STORE_XMSSKEY_PUB, tokenId,
        objId, &storage);
    if (ret == 0) {
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        wp11_storage_close(storage);
    }
    return ret;
}

int wp11_Object_Store_XmssKey(WP11_Object* object, int tokenId,
    int objId)
{
    int ret = 0;
    void* storage = NULL;

    if (object->keyData == NULL)
        ret = wp11_Object_Encode_XmssKey(object);
    if (ret == 0)
        ret = wp11_storage_open(WOLFPKCS11_STORE_XMSSKEY_PUB, tokenId, objId,
            object->keyDataLen, &storage);
    if (ret == 0) {
        ret = wp11_storage_write_array(storage, object->keyData,
            object->keyDataLen);
        ret = wp11_storage_close_write(storage, ret);
    }
    return ret;
}

#endif /* !WOLFPKCS11_NO_STORE */

/* Import an XMSS/XMSS^MT public key from a C_CreateObject template. data[1] is
 * the raw RFC 8391 public key; data[0] (CKA_PARAMETER_SET, the OID as a
 * CK_ULONG) is optional and, when present, is validated against the key.
 * Private-key import is rejected. */
int WP11_Object_SetXmssKey(WP11_Object* object, unsigned char** data,
                           CK_ULONG* len)
{
    int ret = 0;
    XmssKey* newKey = NULL;

    if (object == NULL || data == NULL || len == NULL)
        return BAD_FUNC_ARG;
    if (object->objClass != CKO_PUBLIC_KEY)
        return BAD_FUNC_ARG;
    /* A public key must carry its value; an absent CKA_VALUE is an
     * incomplete template (no keygen path fills it later). Reject it. */
    if (data[1] == NULL)
        return BAD_FUNC_ARG;

    if (object->lock != NULL)
        WP11_Lock_LockRW(object->lock);

    /* Import into a temporary key and swap it in only after it validates, so a
     * failed re-import leaves the existing key unchanged (PKCS#11 requires a
     * failed C_SetAttributeValue to be a no-op). */
    newKey = (XmssKey*)XMALLOC(sizeof(XmssKey), NULL, DYNAMIC_TYPE_KEY);
    if (newKey == NULL)
        ret = MEMORY_E;
    if (ret == 0) {
        XMEMSET(newKey, 0, sizeof(XmssKey));
        ret = wp11_XmssImportPub(newKey, (object->type == CKK_XMSSMT) ? 1 : 0,
            object->devId, data[1], (word32)len[1], data[0], (word32)len[0]);
    }
    if (ret == 0) {
        /* Replace the live key and drop the cached serialization so a later
         * store re-encodes from the new key. */
        if (object->data.xmssKey != NULL) {
        #ifndef WOLFPKCS11_NO_STORE
            if (!object->encoded)
        #endif
                wc_XmssKey_Free(object->data.xmssKey);
            XFREE(object->data.xmssKey, NULL, DYNAMIC_TYPE_KEY);
        }
        object->data.xmssKey = newKey;
        newKey = NULL;
    #ifndef WOLFPKCS11_NO_STORE
        object->encoded = 0;
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = NULL;
        object->keyDataLen = 0;
    #endif
    }
    if (newKey != NULL) {
        wc_XmssKey_Free(newKey);
        XFREE(newKey, NULL, DYNAMIC_TYPE_KEY);
    }

    if (object->lock != NULL)
        WP11_Lock_UnlockRW(object->lock);
    return ret;
}

/**
 * Return the length of an XMSS/XMSS^MT signature in bytes.
 *
 * @param  pub  [in]  XMSS public key object.
 * @return  Length of XMSS signature in bytes, 0 when it cannot be determined.
 */
word32 WP11_Xmss_SigLen(WP11_Object* pub)
{
    word32 len = 0;

    if (pub->lock != NULL)
        WP11_Lock_LockRO(pub->lock);
    if (pub->data.xmssKey == NULL ||
            wc_XmssKey_GetSigLen(pub->data.xmssKey, &len) != 0) {
        len = 0;
    }
    if (pub->lock != NULL)
        WP11_Lock_UnlockRO(pub->lock);

    return len;
}

/* Verify an XMSS/XMSS^MT signature over a raw message. Stateless. */
int WP11_Xmss_Verify(unsigned char* sig, word32 sigLen, unsigned char* data,
                     word32 dataLen, int* stat, WP11_Object* pub)
{
    int ret;
    word32 expSigLen = 0;

    if (pub == NULL || pub->data.xmssKey == NULL || stat == NULL)
        return BAD_FUNC_ARG;

    /* wc_XmssKey_Verify only reads the key and keeps its XmssState local, so
     * concurrent verifies on one object can share the RO lock. */
    if (pub->lock != NULL)
        WP11_Lock_LockRO(pub->lock);

    if (wc_XmssKey_GetSigLen(pub->data.xmssKey, &expSigLen) == 0 &&
            sigLen != expSigLen) {
        *stat = 0;
        ret = 0;
    }
    /* wolfSSL's XMSS verify rejects an empty message with BAD_FUNC_ARG. */
    else if (dataLen == 0) {
        *stat = 0;
        ret = 0;
    }
    else {
        ret = wc_XmssKey_Verify(pub->data.xmssKey, sig, sigLen, data,
            (int)dataLen);
        /* Only SIG_VERIFY_E maps to stat=0; other argument/state errors
         * surface as a function failure so they are not silently reported as
         * an invalid signature. */
        if (ret == 0) {
            *stat = 1;
        }
        else if (ret == SIG_VERIFY_E) {
            *stat = 0;
            ret = 0;
        }
        else {
            *stat = 0;
        }
    }

    if (pub->lock != NULL)
        WP11_Lock_UnlockRO(pub->lock);

    return ret;
}

/* Serve XMSS-specific attributes from a public-key object. */
int wp11_XmssObject_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                            byte* data, CK_ULONG* len)
{
    int ret = 0;

    if (object == NULL || object->data.xmssKey == NULL || len == NULL)
        return BAD_FUNC_ARG;

    switch (type) {
        case CKA_VALUE:
            if (object->objClass == CKO_PUBLIC_KEY) {
                word32 pubLen = 0;
                ret = wc_XmssKey_GetPubLen(object->data.xmssKey, &pubLen);
                if (ret == 0) {
                    if (data == NULL)
                        *len = pubLen;
                    else if (*len < pubLen) {
                        *len = pubLen;
                        ret = BUFFER_E;
                    }
                    else {
                        ret = wc_XmssKey_ExportPubRaw(object->data.xmssKey,
                            data, &pubLen);
                        if (ret == 0)
                            *len = pubLen;
                    }
                }
            }
            else {
                *len = CK_UNAVAILABLE_INFORMATION;
                ret = NOT_AVAILABLE_E;
            }
            break;
        case CKA_PARAMETER_SET: {
            /* The XMSS parameter set is identified by the OID in the leading
             * bytes of the raw public key; return it as a CK_ULONG. */
            CK_ULONG v;
            word32 pubLen = 0;
            byte* raw;

            if (object->objClass != CKO_PUBLIC_KEY) {
                *len = CK_UNAVAILABLE_INFORMATION;
                ret = NOT_AVAILABLE_E;
                break;
            }
            if (data == NULL) {
                *len = sizeof(v);
                break;
            }
            if (*len < sizeof(v)) {
                *len = sizeof(v);
                ret = BUFFER_E;
                break;
            }
            ret = wc_XmssKey_GetPubLen(object->data.xmssKey, &pubLen);
            if (ret == 0 && pubLen < WP11_XMSS_OID_LEN)
                ret = NOT_AVAILABLE_E;
            if (ret == 0) {
                raw = (byte*)XMALLOC(pubLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (raw == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    ret = wc_XmssKey_ExportPubRaw(object->data.xmssKey, raw,
                        &pubLen);
                    if (ret == 0) {
                        v = (CK_ULONG)wp11_HbsReadU32(raw);
                        XMEMCPY(data, &v, sizeof(v));
                        *len = sizeof(v);
                    }
                    XFREE(raw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                }
            }
            break;
        }
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }
    return ret;
}
#endif /* WOLFPKCS11_XMSS */
