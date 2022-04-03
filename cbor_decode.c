/**
 * A module for decoding access rights and public keys from CBOR.
 *
 * Hugely inspired by: https://github.com/PJK/libcbor/blob/master/examples/readfile.c
 */

#include "cbor_decode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cbor.h>

#include <fido/param.h>
#include <fido/eddsa.h>
#include <fido/es256.h>
#include <fido/rs256.h>

static bool check_cbor_parsing_error(const struct cbor_load_result *result) {
  if (result->error.code != CBOR_ERR_NONE) {
    fprintf(
        stderr,
        "There was an error while reading the input near byte %zu (read %zu "
        "bytes in total): ",
        result->error.position, result->read);
    switch (result->error.code) {
      case CBOR_ERR_MALFORMATED: {
        fprintf(stderr, "Malformed data\n");
        break;
      }
      case CBOR_ERR_MEMERROR: {
        printf("Memory error -- perhaps the input is too large?\n");
        break;
      }
      case CBOR_ERR_NODATA: {
        fprintf(stderr, "The input is empty\n");
        break;
      }
      case CBOR_ERR_NOTENOUGHDATA: {
        fprintf(stderr, "Data seem to be missing -- is the input complete?\n");
        break;
      }
      case CBOR_ERR_SYNTAXERROR: {
        fprintf(
	    stderr,
            "Syntactically malformed data -- see "
            "http://tools.ietf.org/html/rfc7049\n");
        break;
      }
      case CBOR_ERR_NONE: {
        // GCC's cheap dataflow analysis gag
        break;
      }
    }
    return false;
  }
  return true;
}

bool decode_cbor_access_rights(
  const uint8_t *data,
  const size_t data_len,
  uint8_t **access_rights,
  size_t *access_rights_len,
  uint8_t **public_key,
  size_t *public_key_len,
  uint8_t **signature,
  size_t *signature_len
) {
  if (!(access_rights && public_key && signature && access_rights_len && public_key_len && signature_len)) {
    return false;
  }
  *access_rights = NULL;
  *public_key = NULL;
  *signature = NULL;


  // Read in CBOR.
  struct cbor_load_result result;
  cbor_item_t* item = cbor_load(data, data_len, &result);

  if (!check_cbor_parsing_error(&result)) {
    return false;
  }

  // The access rights must be encoded as array in the following order:
  // - access rights (binary string)
  // - FIDO credential public key (binary string)
  // - signature from the updater (binary string)

  if (cbor_typeof(item) != CBOR_TYPE_ARRAY || cbor_array_size(item) != 3) {
    fprintf(stderr, "Access rights must be encoded as an array of length 3.\n");
    cbor_decref(&item);
    return false;
  }

  cbor_item_t *item_access_rights = cbor_array_get(item, 0);
  cbor_item_t *item_pub_key = cbor_array_get(item, 1);
  cbor_item_t *item_signature = cbor_array_get(item, 2);

  if (cbor_typeof(item_access_rights) != CBOR_TYPE_BYTESTRING || cbor_bytestring_is_indefinite(item_access_rights)) {
    fprintf(stderr, "Access rights item must be a definite byte string.\n");
    cbor_decref(&item);
    return false;
  }
  if (cbor_typeof(item_pub_key) != CBOR_TYPE_BYTESTRING || cbor_bytestring_is_indefinite(item_pub_key)) {
    fprintf(stderr, "Public key item must be a defininte byte string.\n");
    cbor_decref(&item);
    return false;
  }
  if (cbor_typeof(item_signature) != CBOR_TYPE_BYTESTRING || cbor_bytestring_is_indefinite(item_signature)) {
    fprintf(stderr, "Signature item must be a definite byte string.\n");
    cbor_decref(&item);
    return false;
  }

  // can use malloc here, as the data will by overridden anyways.
  const size_t access_rights_buffer_len = cbor_bytestring_length(item_access_rights);
  uint8_t *access_rights_buffer = (uint8_t*)malloc(access_rights_buffer_len);
  if (!access_rights_buffer) {
    fprintf(stderr, "Could not allocate buffer for access rights.\n");
    cbor_decref(&item);
    return false;
  }

  const size_t public_key_buffer_len = cbor_bytestring_length(item_pub_key);
  uint8_t *public_key_buffer = (uint8_t*)malloc(public_key_buffer_len);
  if (!public_key_buffer) {
    fprintf(stderr, "Could not allocate buffer for public key.\n");
    free(access_rights_buffer);
    cbor_decref(&item);
    return false;
  }

  const size_t signature_buffer_len = cbor_bytestring_length(item_signature);
  uint8_t *signature_buffer = (uint8_t*)malloc(signature_buffer_len);
  if (!public_key_buffer) {
    fprintf(stderr, "Could not allocate buffer for signature.\n");
    free(access_rights_buffer);
    free(public_key_buffer);
    cbor_decref(&item);
    return false;
  }

  memcpy(access_rights_buffer, cbor_bytestring_handle(item_access_rights), access_rights_buffer_len);
  memcpy(public_key_buffer, cbor_bytestring_handle(item_pub_key), public_key_buffer_len);
  memcpy(signature_buffer, cbor_bytestring_handle(item_signature), signature_buffer_len);

  *access_rights = access_rights_buffer;
  *public_key = public_key_buffer;
  *signature = signature_buffer;

  *access_rights_len = access_rights_buffer_len;
  *public_key_len = public_key_buffer_len;
  *signature_len = signature_buffer_len;

  /* Deallocate the result */
  cbor_decref(&item);

  return true;
}

/**
 * Extracts the algorithm from COSE encoded public key.
 * See RFC 8152, and https://www.w3.org/TR/webauthn/#sctn-public-key-easy.
 *
 * Returns `COSE_UNSPEC` if key algorithm cannot be determined.
 */
static int fido_credential_public_key_algorithm(cbor_item_t *item) {
  // Iterate over the map to find alg.
  int alg = COSE_UNSPEC;
  size_t map_size = cbor_map_size(item);
  struct cbor_pair *map_pairs = cbor_map_handle(item);
  for (size_t i = 0; i < map_size; ++i) {
    cbor_item_t *key_item = map_pairs[i].key;
    cbor_item_t *value_item = map_pairs[i].value;
    if (!cbor_isa_uint(key_item)) {
      continue;
    }
    uint8_t key = cbor_get_uint8(key_item);
    if (key != 3 /* the alg field */) {
      continue;
    }
    if (cbor_isa_negint(value_item) == true && cbor_get_int(value_item) <= INT_MAX) {
      // libcbor only extracts positive integers, but we need convert to a negative value.
      alg = -(int)cbor_get_int(value_item) - 1;
    }
  }

  return alg;
}

void *fido_credential_public_key(uint8_t *pub_key, size_t pub_key_len, int *algorithm) {
  if (!algorithm) {
    return NULL;
  }
  // Read in CBOR.
  struct cbor_load_result result;
  cbor_item_t* item = cbor_load(pub_key, pub_key_len, &result);
  if (!check_cbor_parsing_error(&result)) {
    return COSE_UNSPEC;
  }

  if (cbor_typeof(item) != CBOR_TYPE_MAP) {
    fprintf(stderr, "Public key must be encoded as CBOR map.\n");
    cbor_decref(&item);
    return false;
  }

  int read_algorithm = fido_credential_public_key_algorithm(item);
  eddsa_pk_t *eddsa = NULL;
  es256_pk_t *es256 = NULL;
  rs256_pk_t *rs256 = NULL;
  void *pub_key_parsed = NULL;
  bool key_parsing_result = false;

  switch (read_algorithm) {
    case COSE_ES256:
      pub_key_parsed = es256 = es256_pk_new();
      key_parsing_result = es256_pk_decode(item, es256) == FIDO_OK;
      break;
    case COSE_EDDSA:
      pub_key_parsed = eddsa = eddsa_pk_new();
      key_parsing_result = eddsa_pk_decode(item, eddsa) == FIDO_OK;
      break;
    case COSE_RS256:
      pub_key_parsed = rs256 = rs256_pk_new();
      key_parsing_result = rs256_pk_decode(item, rs256) == FIDO_OK;
      break;
    default:
      break;
  }

  if (!key_parsing_result) {
    fprintf(stderr, "Could not read COSE public key.\n");
    fido_credential_public_key_free(&pub_key_parsed, read_algorithm);
  }

  *algorithm = read_algorithm;
  cbor_decref(&item);
  return pub_key_parsed;
}

void fido_credential_public_key_free(void **key, const int algorithm) {
  switch (algorithm) {
    case COSE_EDDSA:
      eddsa_pk_free((eddsa_pk_t**)key);
      break;
    case COSE_ES256:
      es256_pk_free((es256_pk_t**)key);
      break;
    case COSE_RS256:
      rs256_pk_free((rs256_pk_t**)key);
      break;
    default:
      break;
  }
}
