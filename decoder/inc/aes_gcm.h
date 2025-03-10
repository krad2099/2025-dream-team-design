#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts plaintext using AES-GCM.
 *
 * The encryption output is split into two parts:
 *   - ciphertext: the same length as plaintext.
 *   - tag: a 16-byte authentication tag.
 *
 * The IV (nonce) must be 12 bytes.
 *
 * @param key          Pointer to a 16-byte AES key.
 * @param iv           Pointer to a 12-byte IV.
 * @param plaintext    Pointer to the plaintext.
 * @param plaintext_len Length of the plaintext in bytes.
 * @param ciphertext   Pointer to the buffer to hold the ciphertext (plaintext_len bytes).
 * @param tag          Pointer to a 16-byte buffer to receive the auth tag.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int AESGCM_encrypt(const uint8_t *key, const uint8_t *iv, 
                   const uint8_t *plaintext, uint32_t plaintext_len,
                   uint8_t *ciphertext, uint8_t *tag);

/**
 * @brief Decrypts ciphertext using AES-GCM.
 *
 * Expects the same parameters used during encryption.
 *
 * @param key            Pointer to the 16-byte AES key.
 * @param iv             Pointer to the 12-byte IV.
 * @param ciphertext     Pointer to the ciphertext.
 * @param ciphertext_len Length of the ciphertext in bytes.
 * @param tag            Pointer to the 16-byte authentication tag.
 * @param plaintext      Pointer to the buffer for the decrypted plaintext (ciphertext_len bytes).
 *
 * @return 0 on success, non-zero error code on authentication failure or other error.
 */
int AESGCM_decrypt(const uint8_t *key, const uint8_t *iv, 
                   const uint8_t *ciphertext, uint32_t ciphertext_len,
                   const uint8_t *tag, uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif // AES_GCM_H
