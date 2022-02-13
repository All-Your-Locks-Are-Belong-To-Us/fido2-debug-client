#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Decodes CBOR-encoded access rights.
 *
 * All buffers will be allocated for the caller automatically.
 * Freeing them is responsibility of the caller.
 */
bool decode_cbor_access_rights(
  const uint8_t *data,
  const size_t data_len,
  uint8_t **access_rights,
  size_t *access_rights_len,
  uint8_t **public_key,
  size_t *public_key_len,
  uint8_t **signature,
  size_t *signature_len
);

void *fido_credential_public_key(uint8_t *pub_key, size_t pub_key_len, int *algorithm);

void fido_credential_public_key_free(void **key, const int algorithm);
