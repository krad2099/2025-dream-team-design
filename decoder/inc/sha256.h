#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Computes SHA-256 hash of input data.
 *
 * @param data      Pointer to the input data.
 * @param len       Length of the input data in bytes.
 * @param hash_out  Pointer to a buffer (at least 32 bytes) to receive the hash.
 *
 * @return 0 on success, non-zero on failure.
 */
int simple_sha256(const void *data, size_t len, uint8_t *hash_out);

#ifdef __cplusplus
}
#endif

#endif // SHA256_H
