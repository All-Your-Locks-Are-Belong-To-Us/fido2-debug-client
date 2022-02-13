#include "crypto.h"

#include <fido.h>
#include <fido/eddsa.h>
#include <fido/es256.h>
#include <fido/rs256.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "cbor_decode.h"

#ifndef PUBKEY_PATH
#define PUBKEY_PATH "/etc/hotsir/pubkey.pem"
#endif

bool verify_ecdsa_signature(uint8_t *data, size_t data_len, uint8_t* signature, size_t signature_len) {
  // First, read in the signature verification public key.
  FILE *pubkey_file = fopen(PUBKEY_PATH, "r");
  if (!pubkey_file) {
    fprintf(stderr, "Could not open public key file at " PUBKEY_PATH "\n");
    return false;
  }
  // Does not support password at the moment.
  EVP_PKEY *pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
  fclose(pubkey_file);
  if (!pubkey) {
    fprintf(stderr, "Could not read public key from " PUBKEY_PATH "\n");
    return false;
  }

  // Verify the signature.
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

  EVP_VerifyInit(md_ctx, EVP_sha256());
  EVP_VerifyUpdate(md_ctx, data, data_len);

  int verification_result = EVP_VerifyFinal(md_ctx, signature, signature_len, pubkey);
  if (verification_result != 1) {
    fprintf(stderr, "Error verifying signature\n");
    ERR_print_errors_fp(stderr);
  }
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pubkey);

  return verification_result == 1;
}


bool verify_fido_assertion(fido_assert_t *assert, uint8_t *pub_key, size_t pub_key_len) {
  // Convert the public key raw data to something, libfido understands.
  // At the time of writing, there is no way to tell the key types apart provided by libfido.
  // Therefore, libfido was patched to expose that functionaliy.

  bool return_value = false;

  int cose_algorithm = COSE_UNSPEC;
  void *key = fido_credential_public_key(pub_key, pub_key_len, &cose_algorithm);
  if (!key) {
    fprintf(stderr, "Could not read public key.\n");
    goto fail;
  }

  int verification_result = fido_assert_verify(assert, 0, cose_algorithm, key);
  if (verification_result != FIDO_OK) {
    fprintf(stderr, "Could not verify signature of assertion %s.\n", fido_strerr(verification_result));
    goto fail;
  }
  return_value = true;

fail:
  fido_credential_public_key_free(&key, cose_algorithm);
  return return_value;
}
