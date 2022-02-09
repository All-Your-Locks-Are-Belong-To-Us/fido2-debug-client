#pragma once

#include <stdint.h>
#include <stdbool.h>

/**
 * Verifies a signature over data by using the SHA256 algorithm and EC keys.
 *
 * Warning: This function is not thread safe.
 */
bool verify_ecdsa_signature(uint8_t *data, size_t data_len, uint8_t* signature, size_t signature_len);
