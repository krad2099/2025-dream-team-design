#include "simple_crypto.h"
#include <openssl/md5.h>
#include <string.h>

/** @brief Compute MD5 digest of plaintext.
 *
 * Instead of encrypting, this function computes the MD5 hash of the plaintext.
 *
 * @param plaintext Input data.
 * @param len Length of input data.
 * @param key Not used.
 * @param ciphertext Output buffer (must be at least 16 bytes).
 * @return 0 on success.
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    // Compute MD5 hash of plaintext; MD5 digest is 16 bytes.
    MD5(plaintext, len, ciphertext);
    return 0;
}

/** @brief "Decrypt" function for MD5.
 *
 * Since MD5 is not reversible, we simply copy the digest.
 *
 * @param ciphertext Input digest (expected to be 16 bytes).
 * @param len Length of input (should be 16).
 * @param key Not used.
 * @param plaintext Output buffer.
 * @return 0 on success, -1 if len != 16.
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    if (len != 16)
        return -1;
    memcpy(plaintext, ciphertext, 16);
    return 0;
}
