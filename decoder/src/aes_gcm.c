/**
 * @file aes_gcm.c
 * @brief Minimal AES-GCM implementation.
 *
 * This file implements AES-GCM encryption and decryption using a minimal AES-128 (ECB) implementation,
 * a basic GHASH function, and counter-mode processing.
 *
 * Note: This implementation supports only 16‐byte keys and 12‐byte IVs.
 */

#include "aes_gcm.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLOCK_SIZE 16
#define AES_NUM_ROUNDS 10
#define AES_KEY_EXP_SIZE (AES_BLOCK_SIZE * (AES_NUM_ROUNDS + 1))

/* --- Minimal AES-128 Implementation (ECB mode) --- */

static const uint8_t sbox[256] = {
    /* Standard AES S-box */
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

static void AES128_KeyExpansion(const uint8_t *key, uint8_t *roundKeys) {
    memcpy(roundKeys, key, AES_BLOCK_SIZE);
    int bytesGenerated = AES_BLOCK_SIZE;
    int rconIteration = 1;
    uint8_t temp[4];

    while (bytesGenerated < AES_KEY_EXP_SIZE) {
        for (int i = 0; i < 4; i++) {
            temp[i] = roundKeys[bytesGenerated - 4 + i];
        }
        if (bytesGenerated % AES_BLOCK_SIZE == 0) {
            // Rotate left
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // Apply S-box
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            // XOR with Rcon
            temp[0] ^= Rcon[rconIteration];
            rconIteration++;
        }
        for (int i = 0; i < 4; i++) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - AES_BLOCK_SIZE] ^ temp[i];
            bytesGenerated++;
        }
    }
}

static void SubBytes(uint8_t *state) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = sbox[state[i]];
    }
}

static void ShiftRows(uint8_t *state) {
    uint8_t temp[AES_BLOCK_SIZE];
    // Row 0: no shift
    temp[0] = state[0];
    temp[4] = state[4];
    temp[8] = state[8];
    temp[12] = state[12];
    // Row 1: shift left by 1
    temp[1] = state[5];
    temp[5] = state[9];
    temp[9] = state[13];
    temp[13] = state[1];
    // Row 2: shift left by 2
    temp[2] = state[10];
    temp[6] = state[14];
    temp[10] = state[2];
    temp[14] = state[6];
    // Row 3: shift left by 3
    temp[3] = state[15];
    temp[7] = state[3];
    temp[11] = state[7];
    temp[15] = state[11];
    memcpy(state, temp, AES_BLOCK_SIZE);
}

static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x >> 7) & 1 ? 0x1B : 0);
}

static void MixColumns(uint8_t *state) {
    for (int i = 0; i < 4; i++) {
        int index = i * 4;
        uint8_t a0 = state[index];
        uint8_t a1 = state[index+1];
        uint8_t a2 = state[index+2];
        uint8_t a3 = state[index+3];
        uint8_t r0 = xtime(a0) ^ a1 ^ xtime(a1) ^ a2 ^ a3;
        uint8_t r1 = a0 ^ xtime(a1) ^ a2 ^ xtime(a2) ^ a3;
        uint8_t r2 = a0 ^ a1 ^ xtime(a2) ^ a3 ^ xtime(a3);
        uint8_t r3 = a0 ^ xtime(a0) ^ a1 ^ a2 ^ xtime(a3);
        state[index] = r0;
        state[index+1] = r1;
        state[index+2] = r2;
        state[index+3] = r3;
    }
}

static void AddRoundKey(uint8_t *state, const uint8_t *roundKey) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= roundKey[i];
    }
}

static void AES128_ECB_encrypt(const uint8_t *in, uint8_t *out, const uint8_t *roundKeys) {
    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, in, AES_BLOCK_SIZE);
    AddRoundKey(state, roundKeys);
    for (int round = 1; round < AES_NUM_ROUNDS; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * AES_BLOCK_SIZE);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + AES_NUM_ROUNDS * AES_BLOCK_SIZE);
    memcpy(out, state, AES_BLOCK_SIZE);
}

/* --- Helper functions for GCM --- */

// Increment the 32-bit counter in the last 4 bytes of block (big-endian)
static void inc32(uint8_t *block) {
    for (int i = 15; i >= 12; i--) {
        if (++block[i]) break;
    }
}

// XOR two 16-byte blocks: out = a XOR b
static void xor_block(const uint8_t *a, const uint8_t *b, uint8_t *out) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        out[i] = a[i] ^ b[i];
    }
}

// Multiply two 128-bit numbers (X and Y) in GF(2^128) using the polynomial
// R = 0xE1000000000000000000000000000000.
static void gcm_mult(const uint8_t *X, const uint8_t *Y, uint8_t *result) {
    uint8_t Z[16] = {0};
    uint8_t V[16];
    memcpy(V, Y, 16);
    for (int i = 0; i < 16; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            if (X[i] & (1 << bit)) {
                for (int j = 0; j < 16; j++) {
                    Z[j] ^= V[j];
                }
            }
            int lsb = V[15] & 1;
            // Shift V right by one bit.
            for (int j = 15; j > 0; j--) {
                V[j] = (V[j] >> 1) | ((V[j-1] & 1) << 7);
            }
            V[0] >>= 1;
            if (lsb) {
                V[0] ^= 0xE1;
            }
        }
    }
    memcpy(result, Z, 16);
}

// GHASH function. 'data_len' must be a multiple of 16.
static void ghash(const uint8_t *H, const uint8_t *data, size_t data_len, uint8_t *result) {
    uint8_t Y[16] = {0};
    for (size_t i = 0; i < data_len; i += AES_BLOCK_SIZE) {
        uint8_t block[16];
        memcpy(block, data + i, AES_BLOCK_SIZE);
        xor_block(Y, block, Y);
        uint8_t tmp[16];
        gcm_mult(Y, H, tmp);
        memcpy(Y, tmp, 16);
    }
    memcpy(result, Y, 16);
}

/* --- AES-GCM Encrypt/Decrypt Functions --- */

int AESGCM_encrypt(const uint8_t *key, const uint8_t *iv, 
                   const uint8_t *plaintext, uint32_t plaintext_len,
                   uint8_t *ciphertext, uint8_t *tag) {
    int ret = 0;
    uint8_t roundKeys[AES_KEY_EXP_SIZE];
    AES128_KeyExpansion(key, roundKeys);

    // Compute H = AES_ECB_encrypt(0^16)
    uint8_t H[16] = {0};
    uint8_t zero[16] = {0};
    AES128_ECB_encrypt(zero, H, roundKeys);

    // Compute J0. For 12-byte IV, J0 = IV || 0x00000001 (big-endian)
    uint8_t J0[16];
    memcpy(J0, iv, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    // Encrypt plaintext in counter mode.
    uint32_t nblocks = (plaintext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    uint8_t counter[16];
    memcpy(counter, J0, 16);
    for (uint32_t i = 0; i < nblocks; i++) {
        inc32(counter);
        uint8_t keystream[16];
        AES128_ECB_encrypt(counter, keystream, roundKeys);
        uint32_t block_size = (i < nblocks - 1) ? AES_BLOCK_SIZE : (plaintext_len - i * AES_BLOCK_SIZE);
        for (uint32_t j = 0; j < block_size; j++) {
            ciphertext[i * AES_BLOCK_SIZE + j] = plaintext[i * AES_BLOCK_SIZE + j] ^ keystream[j];
        }
    }

    // Prepare GHASH input:
    // Data = ciphertext padded to a multiple of 16 bytes.
    size_t ctext_padded_len = nblocks * AES_BLOCK_SIZE;
    uint8_t *ghash_data = (uint8_t *)malloc(ctext_padded_len + 16);
    if (!ghash_data) return -1;
    memset(ghash_data, 0, ctext_padded_len + 16);
    memcpy(ghash_data, ciphertext, plaintext_len); // pad with zeros automatically

    // Append length block: 64-bit AAD length (0) || 64-bit ciphertext length in bits.
    uint8_t len_block[16] = {0};
    uint64_t bits = ((uint64_t)plaintext_len) * 8;
    // Store bits in big-endian order in the last 8 bytes.
    len_block[8]  = (bits >> 56) & 0xFF;
    len_block[9]  = (bits >> 48) & 0xFF;
    len_block[10] = (bits >> 40) & 0xFF;
    len_block[11] = (bits >> 32) & 0xFF;
    len_block[12] = (bits >> 24) & 0xFF;
    len_block[13] = (bits >> 16) & 0xFF;
    len_block[14] = (bits >> 8)  & 0xFF;
    len_block[15] = bits & 0xFF;
    memcpy(ghash_data + ctext_padded_len, len_block, 16);

    uint8_t S[16];
    ghash(H, ghash_data, ctext_padded_len + 16, S);
    free(ghash_data);

    // Compute tag = AES_ECB_encrypt(J0) XOR S.
    uint8_t E_J0[16];
    AES128_ECB_encrypt(J0, E_J0, roundKeys);
    xor_block(E_J0, S, tag);

    return 0;
}

int AESGCM_decrypt(const uint8_t *key, const uint8_t *iv, 
                   const uint8_t *ciphertext, uint32_t ciphertext_len,
                   const uint8_t *tag, uint8_t *plaintext) {
    int ret = 0;
    uint8_t roundKeys[AES_KEY_EXP_SIZE];
    AES128_KeyExpansion(key, roundKeys);

    // Compute H = AES_ECB_encrypt(0^16)
    uint8_t H[16] = {0};
    uint8_t zero[16] = {0};
    AES128_ECB_encrypt(zero, H, roundKeys);

    // Compute J0.
    uint8_t J0[16];
    memcpy(J0, iv, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    // Decrypt ciphertext in counter mode.
    uint32_t nblocks = (ciphertext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    uint8_t counter[16];
    memcpy(counter, J0, 16);
    for (uint32_t i = 0; i < nblocks; i++) {
        inc32(counter);
        uint8_t keystream[16];
        AES128_ECB_encrypt(counter, keystream, roundKeys);
        uint32_t block_size = (i < nblocks - 1) ? AES_BLOCK_SIZE : (ciphertext_len - i * AES_BLOCK_SIZE);
        for (uint32_t j = 0; j < block_size; j++) {
            plaintext[i * AES_BLOCK_SIZE + j] = ciphertext[i * AES_BLOCK_SIZE + j] ^ keystream[j];
        }
    }

    // Compute GHASH over ciphertext (padded) and length block.
    size_t ctext_padded_len = nblocks * AES_BLOCK_SIZE;
    uint8_t *ghash_data = (uint8_t *)malloc(ctext_padded_len + 16);
    if (!ghash_data) return -1;
    memset(ghash_data, 0, ctext_padded_len + 16);
    memcpy(ghash_data, ciphertext, ciphertext_len);
    uint8_t len_block[16] = {0};
    uint64_t bits = ((uint64_t)ciphertext_len) * 8;
    len_block[8]  = (bits >> 56) & 0xFF;
    len_block[9]  = (bits >> 48) & 0xFF;
    len_block[10] = (bits >> 40) & 0xFF;
    len_block[11] = (bits >> 32) & 0xFF;
    len_block[12] = (bits >> 24) & 0xFF;
    len_block[13] = (bits >> 16) & 0xFF;
    len_block[14] = (bits >> 8)  & 0xFF;
    len_block[15] = bits & 0xFF;
    memcpy(ghash_data + ctext_padded_len, len_block, 16);
    uint8_t S[16];
    ghash(H, ghash_data, ctext_padded_len + 16, S);
    free(ghash_data);

    // Compute expected tag.
    uint8_t E_J0[16];
    AES128_ECB_encrypt(J0, E_J0, roundKeys);
    uint8_t expected_tag[16];
    xor_block(E_J0, S, expected_tag);

    if (memcmp(expected_tag, tag, 16) != 0) {
        return -1; // Authentication failed.
    }
    return 0;
}
