#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "crypto.h"

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
