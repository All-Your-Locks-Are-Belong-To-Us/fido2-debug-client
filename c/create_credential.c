#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "fido_util.h"

void create_credential(fido_dev_t *device) {
  // Create a credential storage
  fido_cred_t *credential = fido_cred_new();
  if (credential == NULL) {
    perror("fido_cred_new");
    return;
  }

  // Prepare the credential.
  // Relying Party.
  int ret = fido_cred_set_rp(credential, "hotsir", "hotsir");
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set rp: %s\n", fido_strerr(ret));
    goto cleanup_credential;
  }

  // Client Data.
  // TODO: See https://www.w3.org/TR/webauthn-2/#CreateCred-DetermineRpId
  uint8_t cd[] = { 1, 2, 3, 4 };
  ret = fido_cred_set_clientdata(credential, cd, sizeof(cd));
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set client data: %s\n", fido_strerr(ret));
    goto cleanup_credential;
  }

  // User.
  uint8_t user_id[] = { 1, 2, 3, 4, 5 };
  ret = fido_cred_set_user(credential, user_id, sizeof(user_id), "FG", "FG", "fg");
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set user: %s\n", fido_strerr(ret));
    goto cleanup_credential;
  }

  // Resident Key / make it discoverable.
  ret = fido_cred_set_rk(credential, FIDO_OPT_TRUE);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set resident key: %s\n", fido_strerr(ret));
    goto cleanup_credential;
  }

  // Credential type.
  ret = fido_cred_set_type(credential, COSE_ES256);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set credential type: %s\n", fido_strerr(ret));
    goto cleanup_credential;
  }

  // Large Blob Key extension.
  // TODO: Use when supported.
  ret = fido_cred_set_extensions(credential, FIDO_EXT_LARGEBLOB_KEY);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set extensions: %s\n", fido_strerr(ret));
    goto cleanup_credential;
  }

  // Write to the open device.
  ret = fido_dev_make_cred(device, credential, NULL);
  if (ret != FIDO_OK) {
    fido_dev_cancel(device);
    fprintf(stderr, "Could not create credential on authenticator: %s\n", fido_strerr(ret));
    goto cleanup_credential;
  }

  // Find and print credential ID.
  size_t id_len = fido_cred_id_len(credential);
  const uint8_t *id = fido_cred_id_ptr(credential);
  char *credential_id_str = convert_to_hex(id, id_len);
  printf("Created credential len %zu with ID: %s\n", id_len, credential_id_str);
  free(credential_id_str);

  // AAGUID
  const unsigned char *aaguid_ptr = fido_cred_aaguid_ptr(credential);
  if (aaguid_ptr) {
    const size_t aaguid_len = fido_cred_aaguid_len(credential);
    char *aaguid_str = convert_to_hex(aaguid_ptr, aaguid_len);
    printf("AAGUID: %s\n", aaguid_str);
    free(aaguid_str);
  }
 
  // PubKey
  const unsigned char *pubkey_ptr = fido_cred_pubkey_ptr(credential);
  if (pubkey_ptr) {
    const size_t pubkey_len = fido_cred_pubkey_len(credential);
    char *pubkey_str = convert_to_hex(pubkey_ptr, pubkey_len);
    printf("PubKey: %s\n", pubkey_str);
    free(pubkey_str);
  }

  // Large Blob Key
  const unsigned char *large_blob_key_ptr = fido_cred_largeblob_key_ptr(credential);
  if (large_blob_key_ptr) {
    const size_t large_blob_key_len = fido_cred_largeblob_key_len(credential);
    char *large_blob_key_str = convert_to_hex(large_blob_key_ptr, large_blob_key_len);
    printf("LargeBlobKey: %s\n", large_blob_key_str);
    free(large_blob_key_str);
  }

  cleanup_credential:
  fido_cred_free(&credential);
}

void reset_device(fido_dev_t *device) {
  printf("Resetting device...\n");
  int ret = fido_dev_reset(device);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not reset authenticator: %s\n", fido_strerr(ret));
  }
}

int main(void) {
   // Initialize FIDO library.
	fido_init(0);
  iterate_devices(create_credential);
  return EXIT_SUCCESS;
}
