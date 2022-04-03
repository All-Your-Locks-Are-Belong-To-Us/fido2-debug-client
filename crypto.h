#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fido.h>

/**
 * Verifies a signature over data by using the SHA256 algorithm and EC keys.
 *
 * Warning: This function is not thread safe.
 */
bool verify_ecdsa_signature(uint8_t *data, size_t data_len, uint8_t* signature, size_t signature_len);

/**
 * Verified a signature over an assertion with a COSE-encoded public key.
 */
bool verify_fido_assertion(fido_assert_t *assert, uint8_t *pub_key, size_t pub_key_len);
