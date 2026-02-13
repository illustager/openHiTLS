#ifndef CRYPT_AES_TBOX_H
#define CRYPT_AES_TBOX_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_AES_CONSTANT_TIME)
#include "crypt_aes.h"

void SetAesKeyExpansionConstantTime(CRYPT_AES_Key *ctx, uint32_t keyLenBits, const uint8_t *key, bool isEncrypt);

void CRYPT_AES_EncryptConstantTime(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

void CRYPT_AES_DecryptConstantTime(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#endif /* HITLS_CRYPTO_AES_CONSTANT_TIME */
#endif