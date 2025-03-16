#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// For this very simple XOR–based “encryption” implementation, we will
// simulate the output format of AES-GCM by prepending a 12-byte IV and appending a 16-byte tag.
// (Note: This is not secure in any real-world scenario.)

#define XOR_CIPHER_IV_SIZE GCM_IV_SIZE    // 12 bytes
#define XOR_CIPHER_TAG_SIZE GCM_TAG_SIZE  // 16 bytes

// Compute a very simple tag: sum all bytes in (IV || ciphertext) modulo 256,
// then repeat that byte to fill the tag.
static void compute_tag(const uint8_t *data, size_t data_len, uint8_t *tag) {
    uint8_t sum = 0;
    for (size_t i = 0; i < data_len; i++) {
        sum += data[i];
    }
    for (size_t i = 0; i < XOR_CIPHER_TAG_SIZE; i++) {
        tag[i] = sum;
    }
}

int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *out) {
    // Generate a random IV and place it in out[0 .. 11]
    for (int i = 0; i < XOR_CIPHER_IV_SIZE; i++) {
        out[i] = rand() & 0xFF; // Note: rand() is not cryptographically secure.
    }
    // Encrypt plaintext: for each byte, compute:
    // ciphertext[i] = plaintext[i] XOR key[i mod KEY_SIZE] XOR IV[i mod 12]
    for (size_t i = 0; i < len; i++) {
        uint8_t k = key[i % KEY_SIZE];
        uint8_t iv = out[i % XOR_CIPHER_IV_SIZE];
        out[XOR_CIPHER_IV_SIZE + i] = plaintext[i] ^ k ^ iv;
    }
    // Compute tag over (IV || ciphertext)
    uint8_t tag[XOR_CIPHER_TAG_SIZE];
    compute_tag(out, XOR_CIPHER_IV_SIZE + len, tag);
    // Append tag after ciphertext
    memcpy(out + XOR_CIPHER_IV_SIZE + len, tag, XOR_CIPHER_TAG_SIZE);
    return 0;
}

int decrypt_sym(const uint8_t *ciphertext, uint16_t cipher_len, const uint8_t *key, uint8_t *plaintext) {
    if (cipher_len < (XOR_CIPHER_IV_SIZE + XOR_CIPHER_TAG_SIZE)) {
        return -1;  // Not enough data.
    }
    size_t total_payload = cipher_len - XOR_CIPHER_IV_SIZE; // ciphertext + tag
    if (total_payload < XOR_CIPHER_TAG_SIZE) {
        return -1;
    }
    size_t cipher_text_len = total_payload - XOR_CIPHER_TAG_SIZE;
    const uint8_t *iv = ciphertext; // First 12 bytes.
    const uint8_t *enc_data = ciphertext + XOR_CIPHER_IV_SIZE;
    uint8_t expected_tag[XOR_CIPHER_TAG_SIZE];
    compute_tag(ciphertext, XOR_CIPHER_IV_SIZE + cipher_text_len, expected_tag);
    if (memcmp(enc_data + cipher_text_len, expected_tag, XOR_CIPHER_TAG_SIZE) != 0) {
        return -1;  // Tag mismatch.
    }
    // Decrypt: plaintext[i] = enc_data[i] XOR key[i mod KEY_SIZE] XOR IV[i mod 12]
    for (size_t i = 0; i < cipher_text_len; i++) {
        uint8_t k = key[i % KEY_SIZE];
        uint8_t iv_byte = iv[i % XOR_CIPHER_IV_SIZE];
        plaintext[i] = enc_data[i] ^ k ^ iv_byte;
    }
    return 0;
}

int hash(void *data, size_t len, uint8_t *hash_out) {
    // A very simple "hash": sum all bytes mod 256, then repeat that value 32 times.
    uint8_t sum = 0;
    uint8_t *d = (uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        sum += d[i];
    }
    for (size_t i = 0; i < 32; i++) {
        hash_out[i] = sum;
    }
    return 0;
}

#endif
