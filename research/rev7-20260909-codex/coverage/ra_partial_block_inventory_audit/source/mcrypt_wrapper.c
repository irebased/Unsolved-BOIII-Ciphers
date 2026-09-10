/*
 * WASM wrapper for libmcrypt ciphers.
 * Each cipher .c file is compiled separately; this file provides
 * block cipher modes (CFB8, ECB, CBC, CFB, OFB, CTR) and the
 * exported WASM API.
 *
 * Keys are null-padded to the cipher's nearest supported key size,
 * matching how PHP mcrypt and other tools handle short keys. The
 * variable-key ciphers (blowfish, blowfish-compat, cast-128, rc2,
 * arcfour) are the exception: they get the key at the length given,
 * and stretch it themselves. js/app.js flags those as rawKey so its
 * brute forcer can offer null-padding them as a separate variant.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <emscripten.h>

typedef unsigned int word32;
typedef unsigned short word16;
typedef unsigned char byte;

/* Cipher struct headers */
#include "des.h"
#include "blowfish.h"
#include "serpent.h"
#include "twofish.h"
#include "saferplus.h"
#include "arcfour.h"
#include "cast-128.h"
#include "cast-256.h"
#include "rijndael.h"
#include "safer.h"
#include "tripledes.h"
#include "enigma.h"
#include "panama.h"
#include "wake.h"

/* ========================================================
 * Extern declarations for all cipher modules
 * ======================================================== */

/* XXTEA (standalone, not libmcrypt) */
extern uint8_t *xxtea_encrypt_bytes(const uint8_t *data, size_t data_len,
                                    const uint8_t *key, size_t key_len,
                                    size_t *out_len);
extern uint8_t *xxtea_decrypt_bytes(const uint8_t *data, size_t data_len,
                                    const uint8_t *key, size_t key_len,
                                    size_t *out_len);

/* --- Block cipher encrypt functions --- */

extern int des_LTX__mcrypt_set_key(DES_KEY *dkey, const void *user_key, int len);
extern void des_LTX__mcrypt_encrypt(DES_KEY *key, void *block);
extern void des_LTX__mcrypt_decrypt(DES_KEY *key, void *block);

extern int blowfish_LTX__mcrypt_set_key(blf_ctx *c, const void *k, int len);
extern void blowfish_LTX__mcrypt_encrypt(blf_ctx *c, void *x);
extern void blowfish_LTX__mcrypt_decrypt(blf_ctx *c, void *x);

extern int blowfish_compat_LTX__mcrypt_set_key(blf_ctx *c, const void *k, int len);
extern void blowfish_compat_LTX__mcrypt_encrypt(blf_ctx *c, void *x);
extern void blowfish_compat_LTX__mcrypt_decrypt(blf_ctx *c, void *x);

extern int rc2_LTX__mcrypt_set_key(void *xkey, const void *key, int len);
extern void rc2_LTX__mcrypt_encrypt(const void *xkey, void *plain);
extern void rc2_LTX__mcrypt_decrypt(const void *xkey, void *plain);

extern int serpent_LTX__mcrypt_set_key(SERPENT_KEY *spkey, const void *in_key, int key_len);
extern void serpent_LTX__mcrypt_encrypt(SERPENT_KEY *spkey, void *in_blk);
extern void serpent_LTX__mcrypt_decrypt(SERPENT_KEY *spkey, void *in_blk);

extern int twofish_LTX__mcrypt_set_key(TWI *pkey, const void *in_key, int key_len);
extern void twofish_LTX__mcrypt_encrypt(TWI *pkey, void *in_blk);
extern void twofish_LTX__mcrypt_decrypt(TWI *pkey, void *in_blk);

extern int loki97_LTX__mcrypt_set_key(void *l_key, const void *in_key, int key_len);
extern void loki97_LTX__mcrypt_encrypt(void *l_key, void *block);
extern void loki97_LTX__mcrypt_decrypt(void *l_key, void *block);

extern int saferplus_LTX__mcrypt_set_key(SPI *sp_key, const void *in_key, int key_len);
extern void saferplus_LTX__mcrypt_encrypt(SPI *sp_key, void *block);
extern void saferplus_LTX__mcrypt_decrypt(SPI *sp_key, void *block);

extern int xtea_LTX__mcrypt_set_key(void *k, const void *input_key, int len);
extern void xtea_LTX__mcrypt_encrypt(void *k, void *v);
extern void xtea_LTX__mcrypt_decrypt(void *k, void *v);

extern int threeway_LTX__mcrypt_set_key(word32 *k, word32 *input_key, int len);
extern void threeway_LTX__mcrypt_encrypt(word32 *tk, word32 *ta);
extern void threeway_LTX__mcrypt_decrypt(word32 *tk, word32 *ta);

extern int cast_128_LTX__mcrypt_set_key(CAST_KEY *key, byte *rawkey, unsigned keybytes);
extern void cast_128_LTX__mcrypt_encrypt(CAST_KEY *key, byte *block);
extern void cast_128_LTX__mcrypt_decrypt(CAST_KEY *key, byte *block);

extern int cast_256_LTX__mcrypt_set_key(cast256_key *key, const word32 *in_key, int key_len);
extern void cast_256_LTX__mcrypt_encrypt(cast256_key *key, word32 *blk);
extern void cast_256_LTX__mcrypt_decrypt(cast256_key *key, word32 *blk);

extern int gost_LTX__mcrypt_set_key(word32 *inst, word32 *key, int len);
extern void gost_LTX__mcrypt_encrypt(word32 const key[8], word32 *in);
extern void gost_LTX__mcrypt_decrypt(word32 const key[8], word32 *in);

extern int rijndael_128_LTX__mcrypt_set_key(RI *rinst, byte *key, int nk);
extern void rijndael_128_LTX__mcrypt_encrypt(RI *rinst, byte *buff);
extern void rijndael_128_LTX__mcrypt_decrypt(RI *rinst, byte *buff);

extern int rijndael_192_LTX__mcrypt_set_key(RI *rinst, byte *key, int nk);
extern void rijndael_192_LTX__mcrypt_encrypt(RI *rinst, byte *buff);
extern void rijndael_192_LTX__mcrypt_decrypt(RI *rinst, byte *buff);

extern int rijndael_256_LTX__mcrypt_set_key(RI *rinst, byte *key, int nk);
extern void rijndael_256_LTX__mcrypt_encrypt(RI *rinst, byte *buff);
extern void rijndael_256_LTX__mcrypt_decrypt(RI *rinst, byte *buff);

extern int safer_sk64_LTX__mcrypt_set_key(byte *key, byte *userkey, int len);
extern void safer_sk64_LTX__mcrypt_encrypt(const byte *key, byte *block_in);
extern void safer_sk64_LTX__mcrypt_decrypt(const byte *key, byte *block_in);

extern int safer_sk128_LTX__mcrypt_set_key(byte *key, byte *userkey, int len);
extern void safer_sk128_LTX__mcrypt_encrypt(const byte *key, byte *block_in);
extern void safer_sk128_LTX__mcrypt_decrypt(const byte *key, byte *block_in);

extern int tripledes_LTX__mcrypt_set_key(TRIPLEDES_KEY *dkey, char *user_key, int len);
extern void tripledes_LTX__mcrypt_encrypt(TRIPLEDES_KEY *key, char *block);
extern void tripledes_LTX__mcrypt_decrypt(TRIPLEDES_KEY *key, char *block);

/* --- Stream ciphers --- */

extern int arcfour_LTX__mcrypt_set_key(arcfour_key *key, void *key_data, int key_len, void *IV, int iv_len);
extern void arcfour_LTX__mcrypt_encrypt(arcfour_key *key, void *buffer_ptr, int buffer_len);

extern int enigma_LTX__mcrypt_set_key(CRYPT_KEY *ckey, char *password, int plen, void *u1, int u2);
extern void enigma_LTX__mcrypt_encrypt(CRYPT_KEY *ckey, void *gtext, int textlen);

extern int panama_LTX__mcrypt_set_key(PANAMA_KEY *pan_key, char *in_key, int keysize, char *init_vec, int vecsize);
extern void panama_LTX__mcrypt_encrypt(PANAMA_KEY *pan_key, byte *buf, int length);

extern int wake_LTX__mcrypt_set_key(WAKE_KEY *wake_key, word32 *key, int len, word32 *IV, int ivlen);
extern void wake_LTX__mcrypt_encrypt(WAKE_KEY *wake_key, byte *input, int len);
extern void wake_LTX__mcrypt_decrypt(WAKE_KEY *wake_key, byte *input, int len);

/* ========================================================
 * Shared buffers for JS - WASM data transfer
 * ======================================================== */

#define MAX_BUF 65536
static byte shared_buf[MAX_BUF];
static byte shared_iv[32];
static byte shared_key[256];

EMSCRIPTEN_KEEPALIVE byte* get_buf(void) { return shared_buf; }
EMSCRIPTEN_KEEPALIVE byte* get_iv(void) { return shared_iv; }
EMSCRIPTEN_KEEPALIVE byte* get_key(void) { return shared_key; }

/* ========================================================
 * Key padding: pad to nearest supported key size.
 * Returns the padded key length.
 * ======================================================== */

static int pad_key_16_24_32(byte *key_buf, int keylen) {
    int target;
    if (keylen <= 16)      target = 16;
    else if (keylen <= 24) target = 24;
    else                   target = 32;
    if (keylen < target)
        memset(key_buf + keylen, 0, target - keylen);
    return target;
}

static int pad_key_fixed(byte *key_buf, int keylen, int fixed_size) {
    if (keylen < fixed_size)
        memset(key_buf + keylen, 0, fixed_size - keylen);
    return fixed_size;
}

/* ========================================================
 * Mode constants
 * ======================================================== */

#define MODE_CFB8 0
#define MODE_ECB  1
#define MODE_CBC  2
#define MODE_CFB  3
#define MODE_OFB  4
#define MODE_CTR  5

/* ========================================================
 * Zero-padding (matches PHP mcrypt behavior)
 * ======================================================== */

static int zero_pad(byte *data, int datalen, int block_size) {
    if (datalen % block_size == 0) return datalen;
    int padded = datalen + (block_size - datalen % block_size);
    memset(data + datalen, 0, padded - datalen);
    return padded;
}

static int zero_unpad(byte *data, int datalen) {
    while (datalen > 0 && data[datalen - 1] == 0) datalen--;
    return datalen > 0 ? datalen : 0;
}

/* ========================================================
 * Block cipher mode macros
 * ======================================================== */

/* CFB8 — 8-bit cipher feedback (existing mode) */

#define CFB8_ENCRYPT(ctx_ptr, encrypt_fn, data, data_len, iv, block_size) \
    do { \
        byte *_s = (byte *)malloc(block_size); \
        byte *_e = (byte *)malloc(block_size); \
        memcpy(_s, iv, block_size); \
        for (int _j = 0; _j < data_len; _j++) { \
            memcpy(_e, _s, block_size); \
            encrypt_fn(ctx_ptr, _e); \
            data[_j] ^= _e[0]; \
            for (int _i = 0; _i < block_size - 1; _i++) \
                _s[_i] = _s[_i + 1]; \
            _s[block_size - 1] = data[_j]; \
        } \
        free(_s); \
        free(_e); \
    } while(0)

#define CFB8_DECRYPT(ctx_ptr, encrypt_fn, data, data_len, iv, block_size) \
    do { \
        byte *_s = (byte *)malloc(block_size); \
        byte *_e = (byte *)malloc(block_size); \
        memcpy(_s, iv, block_size); \
        for (int _j = 0; _j < data_len; _j++) { \
            memcpy(_e, _s, block_size); \
            encrypt_fn(ctx_ptr, _e); \
            for (int _i = 0; _i < block_size - 1; _i++) \
                _s[_i] = _s[_i + 1]; \
            _s[block_size - 1] = data[_j]; \
            data[_j] ^= _e[0]; \
        } \
        free(_s); \
        free(_e); \
    } while(0)

/* ECB — Electronic Codebook (data must be padded to block_size multiple) */

#define ECB_ENCRYPT(ctx_ptr, encrypt_fn, data, data_len, block_size) \
    do { \
        for (int _j = 0; _j < data_len; _j += block_size) \
            encrypt_fn(ctx_ptr, data + _j); \
    } while(0)

#define ECB_DECRYPT(ctx_ptr, decrypt_fn, data, data_len, block_size) \
    do { \
        for (int _j = 0; _j < data_len; _j += block_size) \
            decrypt_fn(ctx_ptr, data + _j); \
    } while(0)

/* CBC — Cipher Block Chaining (data must be padded to block_size multiple) */

#define CBC_ENCRYPT(ctx_ptr, encrypt_fn, data, data_len, iv, block_size) \
    do { \
        byte *_prev = (byte *)malloc(block_size); \
        memcpy(_prev, iv, block_size); \
        for (int _j = 0; _j < data_len; _j += block_size) { \
            for (int _i = 0; _i < block_size; _i++) \
                data[_j + _i] ^= _prev[_i]; \
            encrypt_fn(ctx_ptr, data + _j); \
            memcpy(_prev, data + _j, block_size); \
        } \
        free(_prev); \
    } while(0)

#define CBC_DECRYPT(ctx_ptr, decrypt_fn, data, data_len, iv, block_size) \
    do { \
        byte *_prev = (byte *)malloc(block_size); \
        byte *_tmp = (byte *)malloc(block_size); \
        memcpy(_prev, iv, block_size); \
        for (int _j = 0; _j < data_len; _j += block_size) { \
            memcpy(_tmp, data + _j, block_size); \
            decrypt_fn(ctx_ptr, data + _j); \
            for (int _i = 0; _i < block_size; _i++) \
                data[_j + _i] ^= _prev[_i]; \
            memcpy(_prev, _tmp, block_size); \
        } \
        free(_prev); \
        free(_tmp); \
    } while(0)

/* CFB — Full-block Cipher Feedback (no padding needed) */

#define CFB_ENCRYPT(ctx_ptr, encrypt_fn, data, data_len, iv, block_size) \
    do { \
        byte *_sr = (byte *)malloc(block_size); \
        byte *_ks = (byte *)malloc(block_size); \
        memcpy(_sr, iv, block_size); \
        for (int _j = 0; _j < data_len; _j += block_size) { \
            memcpy(_ks, _sr, block_size); \
            encrypt_fn(ctx_ptr, _ks); \
            int _chunk = (data_len - _j < block_size) ? data_len - _j : block_size; \
            for (int _i = 0; _i < _chunk; _i++) \
                data[_j + _i] ^= _ks[_i]; \
            memset(_sr, 0, block_size); \
            memcpy(_sr, data + _j, _chunk); \
        } \
        free(_sr); \
        free(_ks); \
    } while(0)

#define CFB_DECRYPT(ctx_ptr, encrypt_fn, data, data_len, iv, block_size) \
    do { \
        byte *_sr = (byte *)malloc(block_size); \
        byte *_ks = (byte *)malloc(block_size); \
        byte *_ct = (byte *)malloc(block_size); \
        memcpy(_sr, iv, block_size); \
        for (int _j = 0; _j < data_len; _j += block_size) { \
            int _chunk = (data_len - _j < block_size) ? data_len - _j : block_size; \
            memset(_ct, 0, block_size); \
            memcpy(_ct, data + _j, _chunk); \
            memcpy(_ks, _sr, block_size); \
            encrypt_fn(ctx_ptr, _ks); \
            for (int _i = 0; _i < _chunk; _i++) \
                data[_j + _i] ^= _ks[_i]; \
            memcpy(_sr, _ct, block_size); \
        } \
        free(_sr); \
        free(_ks); \
        free(_ct); \
    } while(0)

/* OFB — Output Feedback (encrypt and decrypt are identical) */

#define OFB_PROCESS(ctx_ptr, encrypt_fn, data, data_len, iv, block_size) \
    do { \
        byte *_sr = (byte *)malloc(block_size); \
        memcpy(_sr, iv, block_size); \
        for (int _j = 0; _j < data_len; _j += block_size) { \
            encrypt_fn(ctx_ptr, _sr); \
            int _chunk = (data_len - _j < block_size) ? data_len - _j : block_size; \
            for (int _i = 0; _i < _chunk; _i++) \
                data[_j + _i] ^= _sr[_i]; \
        } \
        free(_sr); \
    } while(0)

/* CTR — Counter mode (encrypt and decrypt are identical) */

#define CTR_PROCESS(ctx_ptr, encrypt_fn, data, data_len, iv, block_size) \
    do { \
        byte *_ctr = (byte *)malloc(block_size); \
        byte *_ks = (byte *)malloc(block_size); \
        memcpy(_ctr, iv, block_size); \
        for (int _j = 0; _j < data_len; _j += block_size) { \
            memcpy(_ks, _ctr, block_size); \
            encrypt_fn(ctx_ptr, _ks); \
            int _chunk = (data_len - _j < block_size) ? data_len - _j : block_size; \
            for (int _i = 0; _i < _chunk; _i++) \
                data[_j + _i] ^= _ks[_i]; \
            for (int _i = block_size - 1; _i >= 0; _i--) { \
                if (++_ctr[_i] != 0) break; \
            } \
        } \
        free(_ctr); \
        free(_ks); \
    } while(0)

/* ========================================================
 * Mode dispatch macro — used by each block cipher.
 * Returns the output length or -1 on error.
 * ======================================================== */

#define BLOCK_DISPATCH(ctx, enc_fn, dec_fn, data, dlen, iv, bs, encrypt, mode) \
    do { \
        switch (mode) { \
        case MODE_CFB8: \
            if (encrypt) CFB8_ENCRYPT(ctx, enc_fn, data, dlen, iv, bs); \
            else         CFB8_DECRYPT(ctx, enc_fn, data, dlen, iv, bs); \
            return dlen; \
        case MODE_ECB: \
            if (encrypt) { \
                int _plen = zero_pad(data, dlen, bs); \
                ECB_ENCRYPT(ctx, enc_fn, data, _plen, bs); \
                return _plen; \
            } else { \
                if (dlen % bs != 0) return -1; \
                ECB_DECRYPT(ctx, dec_fn, data, dlen, bs); \
                return zero_unpad(data, dlen); \
            } \
        case MODE_CBC: \
            if (encrypt) { \
                int _plen = zero_pad(data, dlen, bs); \
                CBC_ENCRYPT(ctx, enc_fn, data, _plen, iv, bs); \
                return _plen; \
            } else { \
                if (dlen % bs != 0) return -1; \
                CBC_DECRYPT(ctx, dec_fn, data, dlen, iv, bs); \
                return zero_unpad(data, dlen); \
            } \
        case MODE_CFB: \
            if (encrypt) CFB_ENCRYPT(ctx, enc_fn, data, dlen, iv, bs); \
            else         CFB_DECRYPT(ctx, enc_fn, data, dlen, iv, bs); \
            return dlen; \
        case MODE_OFB: \
            OFB_PROCESS(ctx, enc_fn, data, dlen, iv, bs); \
            return dlen; \
        case MODE_CTR: \
            CTR_PROCESS(ctx, enc_fn, data, dlen, iv, bs); \
            return dlen; \
        default: return -1; \
        } \
    } while(0)

/* ========================================================
 * Block-pointer adapter wrappers for ciphers whose encrypt/
 * decrypt functions take word32* or char* instead of byte*.
 * ======================================================== */

static void threeway_encrypt_wrap(word32 *ctx, byte *block) {
    threeway_LTX__mcrypt_encrypt(ctx, (word32 *)block);
}
static void threeway_decrypt_wrap(word32 *ctx, byte *block) {
    threeway_LTX__mcrypt_decrypt(ctx, (word32 *)block);
}

static void gost_encrypt_wrap(word32 *ctx, byte *block) {
    gost_LTX__mcrypt_encrypt(ctx, (word32 *)block);
}
static void gost_decrypt_wrap(word32 *ctx, byte *block) {
    gost_LTX__mcrypt_decrypt(ctx, (word32 *)block);
}

static void cast256_encrypt_wrap(cast256_key *ctx, byte *block) {
    cast_256_LTX__mcrypt_encrypt(ctx, (word32 *)block);
}
static void cast256_decrypt_wrap(cast256_key *ctx, byte *block) {
    cast_256_LTX__mcrypt_decrypt(ctx, (word32 *)block);
}

static void tripledes_encrypt_wrap(TRIPLEDES_KEY *ctx, byte *block) {
    tripledes_LTX__mcrypt_encrypt(ctx, (char *)block);
}
static void tripledes_decrypt_wrap(TRIPLEDES_KEY *ctx, byte *block) {
    tripledes_LTX__mcrypt_decrypt(ctx, (char *)block);
}

/* ========================================================
 * Exported block cipher functions
 * Each returns the output length, or -1 on error.
 * ======================================================== */

EMSCRIPTEN_KEEPALIVE int threeway_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    word32 ctx[3];
    int kl = pad_key_fixed(shared_key, keylen, 12);
    threeway_LTX__mcrypt_set_key(ctx, (word32 *)shared_key, kl);
    BLOCK_DISPATCH(ctx, threeway_encrypt_wrap, threeway_decrypt_wrap, shared_buf, datalen, shared_iv, 12, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int des_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    DES_KEY ctx;
    int kl = pad_key_fixed(shared_key, keylen, 8);
    des_LTX__mcrypt_set_key(&ctx, shared_key, kl);
    BLOCK_DISPATCH(&ctx, des_LTX__mcrypt_encrypt, des_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 8, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int tripledes_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    TRIPLEDES_KEY ctx;
    int kl = pad_key_fixed(shared_key, keylen, 24);
    tripledes_LTX__mcrypt_set_key(&ctx, (char *)shared_key, kl);
    BLOCK_DISPATCH(&ctx, tripledes_encrypt_wrap, tripledes_decrypt_wrap, shared_buf, datalen, shared_iv, 8, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int blowfish_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    blf_ctx ctx;
    blowfish_LTX__mcrypt_set_key(&ctx, shared_key, keylen);
    BLOCK_DISPATCH(&ctx, blowfish_LTX__mcrypt_encrypt, blowfish_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 8, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int blowfish_compat_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    blf_ctx ctx;
    blowfish_compat_LTX__mcrypt_set_key(&ctx, shared_key, keylen);
    BLOCK_DISPATCH(&ctx, blowfish_compat_LTX__mcrypt_encrypt, blowfish_compat_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 8, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int cast128_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    CAST_KEY ctx;
    cast_128_LTX__mcrypt_set_key(&ctx, shared_key, keylen);
    BLOCK_DISPATCH(&ctx, cast_128_LTX__mcrypt_encrypt, cast_128_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 8, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int cast256_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    cast256_key ctx;
    int kl = pad_key_16_24_32(shared_key, keylen);
    cast_256_LTX__mcrypt_set_key(&ctx, (word32 *)shared_key, kl);
    BLOCK_DISPATCH(&ctx, cast256_encrypt_wrap, cast256_decrypt_wrap, shared_buf, datalen, shared_iv, 16, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int gost_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    word32 ctx[8];
    int kl = pad_key_fixed(shared_key, keylen, 32);
    gost_LTX__mcrypt_set_key(ctx, (word32 *)shared_key, kl);
    BLOCK_DISPATCH(ctx, gost_encrypt_wrap, gost_decrypt_wrap, shared_buf, datalen, shared_iv, 8, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int rc2_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    word16 ctx[64];
    rc2_LTX__mcrypt_set_key(ctx, shared_key, keylen);
    BLOCK_DISPATCH(ctx, rc2_LTX__mcrypt_encrypt, rc2_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 8, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int rijndael128_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    RI ctx;
    memset(&ctx, 0, sizeof(RI));
    int kl = pad_key_16_24_32(shared_key, keylen);
    rijndael_128_LTX__mcrypt_set_key(&ctx, shared_key, kl);
    BLOCK_DISPATCH(&ctx, rijndael_128_LTX__mcrypt_encrypt, rijndael_128_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 16, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int rijndael192_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    RI ctx;
    memset(&ctx, 0, sizeof(RI));
    int kl = pad_key_16_24_32(shared_key, keylen);
    rijndael_192_LTX__mcrypt_set_key(&ctx, shared_key, kl);
    BLOCK_DISPATCH(&ctx, rijndael_192_LTX__mcrypt_encrypt, rijndael_192_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 24, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int rijndael256_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    RI ctx;
    memset(&ctx, 0, sizeof(RI));
    int kl = pad_key_16_24_32(shared_key, keylen);
    rijndael_256_LTX__mcrypt_set_key(&ctx, shared_key, kl);
    BLOCK_DISPATCH(&ctx, rijndael_256_LTX__mcrypt_encrypt, rijndael_256_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 32, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int safer64_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    byte ctx[SAFER_KEY_LEN];
    memset(ctx, 0, SAFER_KEY_LEN);
    int kl = pad_key_fixed(shared_key, keylen, 8);
    safer_sk64_LTX__mcrypt_set_key(ctx, shared_key, kl);
    BLOCK_DISPATCH(ctx, safer_sk64_LTX__mcrypt_encrypt, safer_sk64_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 8, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int safer128_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    byte ctx[SAFER_KEY_LEN];
    memset(ctx, 0, SAFER_KEY_LEN);
    int kl = pad_key_fixed(shared_key, keylen, 16);
    safer_sk128_LTX__mcrypt_set_key(ctx, shared_key, kl);
    BLOCK_DISPATCH(ctx, safer_sk128_LTX__mcrypt_encrypt, safer_sk128_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 8, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int serpent_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    SERPENT_KEY ctx;
    int kl = pad_key_16_24_32(shared_key, keylen);
    serpent_LTX__mcrypt_set_key(&ctx, shared_key, kl);
    BLOCK_DISPATCH(&ctx, serpent_LTX__mcrypt_encrypt, serpent_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 16, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int twofish_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    TWI ctx;
    memset(&ctx, 0, sizeof(TWI));
    int kl = pad_key_16_24_32(shared_key, keylen);
    twofish_LTX__mcrypt_set_key(&ctx, shared_key, kl);
    BLOCK_DISPATCH(&ctx, twofish_LTX__mcrypt_encrypt, twofish_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 16, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int loki97_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    word32 ctx[96];
    memset(ctx, 0, sizeof(ctx));
    int kl = pad_key_16_24_32(shared_key, keylen);
    loki97_LTX__mcrypt_set_key(ctx, shared_key, kl);
    BLOCK_DISPATCH(ctx, loki97_LTX__mcrypt_encrypt, loki97_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 16, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int saferplus_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    SPI ctx;
    memset(&ctx, 0, sizeof(SPI));
    int kl = pad_key_16_24_32(shared_key, keylen);
    saferplus_LTX__mcrypt_set_key(&ctx, shared_key, kl);
    BLOCK_DISPATCH(&ctx, saferplus_LTX__mcrypt_encrypt, saferplus_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 16, encrypt, mode);
}

EMSCRIPTEN_KEEPALIVE int xtea_process(int keylen, int ivlen, int datalen, int encrypt, int mode) {
    word32 ctx[4];
    int kl = pad_key_fixed(shared_key, keylen, 16);
    xtea_LTX__mcrypt_set_key(ctx, shared_key, kl);
    BLOCK_DISPATCH(ctx, xtea_LTX__mcrypt_encrypt, xtea_LTX__mcrypt_decrypt, shared_buf, datalen, shared_iv, 8, encrypt, mode);
}

/* ========================================================
 * Exported stream cipher functions
 * ======================================================== */

EMSCRIPTEN_KEEPALIVE int rc4_process(int keylen, int datalen, int encrypt) {
    arcfour_key ctx;
    arcfour_LTX__mcrypt_set_key(&ctx, shared_key, keylen, NULL, 0);
    arcfour_LTX__mcrypt_encrypt(&ctx, shared_buf, datalen);
    return 0;
}

EMSCRIPTEN_KEEPALIVE int enigma_process(int keylen, int datalen, int encrypt) {
    CRYPT_KEY ctx;
    enigma_LTX__mcrypt_set_key(&ctx, (char *)shared_key, keylen, NULL, 0);
    enigma_LTX__mcrypt_encrypt(&ctx, shared_buf, datalen);
    return 0;
}

EMSCRIPTEN_KEEPALIVE int panama_process(int keylen, int datalen, int encrypt) {
    PANAMA_KEY ctx;
    memset(&ctx, 0, sizeof(PANAMA_KEY));
    int kl = pad_key_fixed(shared_key, keylen, 32);
    panama_LTX__mcrypt_set_key(&ctx, (char *)shared_key, kl, NULL, 0);
    panama_LTX__mcrypt_encrypt(&ctx, shared_buf, datalen);
    return 0;
}

EMSCRIPTEN_KEEPALIVE int wake_process(int keylen, int datalen, int encrypt) {
    WAKE_KEY ctx;
    memset(&ctx, 0, sizeof(WAKE_KEY));
    int kl = pad_key_fixed(shared_key, keylen, 32);
    wake_LTX__mcrypt_set_key(&ctx, (word32 *)shared_key, kl, NULL, 0);
    if (encrypt)
        wake_LTX__mcrypt_encrypt(&ctx, shared_buf, datalen);
    else
        wake_LTX__mcrypt_decrypt(&ctx, shared_buf, datalen);
    return 0;
}

/* ========================================================
 * XXTEA — variable-length block cipher, no IV.
 * Returns the output length (written into shared_buf).
 * ======================================================== */

EMSCRIPTEN_KEEPALIVE int xxtea_process(int keylen, int datalen, int encrypt) {
    size_t out_len = 0;
    uint8_t *result;
    if (datalen <= 0) return -1;
    if (encrypt) {
        result = xxtea_encrypt_bytes(shared_buf, (size_t)datalen, shared_key, (size_t)keylen, &out_len);
    } else {
        result = xxtea_decrypt_bytes(shared_buf, (size_t)datalen, shared_key, (size_t)keylen, &out_len);
    }
    if (!result) return -1;
    if (out_len > MAX_BUF) out_len = MAX_BUF;
    memcpy(shared_buf, result, out_len);
    free(result);
    return (int)out_len;
}
