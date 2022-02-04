#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "fido_util.h"

static char *credential_id = NULL;

static void read_credential(fido_dev_t *device){
  if (credential_id == NULL) {
    return;
  }

  size_t id_len;
  uint8_t *hex_id = convert_from_hex(credential_id, &id_len);
  if (id_len == 0) {
    fprintf(stderr, "Could not parse HEX from credential id.\n");
    return;
  }

  printf("Reading credential with id %s\n", credential_id);

  // Create an assertion.
  fido_assert_t *assert = fido_assert_new();
  if (!assert) {
    goto cleanup_read_credential;
  }

  // Set client data.
  uint8_t client_data[] = { 1, 2, 3 };
  int ret = fido_assert_set_clientdata(assert, client_data, sizeof(client_data));
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set client data: %s\n", fido_strerr(ret));
    goto cleanup_read_credential;
  }

  // Set relying party.
  ret = fido_assert_set_rp(assert, RPID);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set client data: %s\n", fido_strerr(ret));
    goto cleanup_read_credential;
  }

  // Set which credentials are allowed.
  ret = fido_assert_allow_cred(assert, hex_id, id_len);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set allowed credentials: %s\n", fido_strerr(ret));
    goto cleanup_read_credential;
  }

  // Force user presence.
  ret = fido_assert_set_up(assert, FIDO_OPT_TRUE);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set user presence: %s\n", fido_strerr(ret));
    goto cleanup_read_credential;
  }

  ret = fido_assert_set_extensions(assert, FIDO_EXT_LARGEBLOB_KEY);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not enable largeBlobKey extension: %s\n", fido_strerr(ret));
    goto cleanup_read_credential;
  }

  // Send assertion to authenticator.
  ret = fido_dev_get_assert(device, assert, NULL);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not get assertion from authenticator: %s\n", fido_strerr(ret));
    goto cleanup_read_credential;
  }

  // Get user and stuff from assertion.
  printf("User: %s (display name: %s)\n", fido_assert_user_name(assert, 0), fido_assert_user_display_name(assert, 0));
  printf("Sigcount %d and user_id len %zu\n", fido_assert_sigcount(assert, 0), fido_assert_user_id_len(assert, 0));

  const unsigned char *large_blob_key_ptr = fido_assert_largeblob_key_ptr(assert, 0);
  if (large_blob_key_ptr) {
    const size_t large_blob_key_len = fido_assert_largeblob_key_len(assert, 0);
    char *large_blob_key_str = convert_to_hex(large_blob_key_ptr, large_blob_key_len);
    printf("largeBlobKey: %s\n", large_blob_key_str);
    free(large_blob_key_str);
  }

  cleanup_read_credential:
  fido_assert_free(&assert);
  free(hex_id);
}

static void usage(const char *program_name) {
  fprintf(stderr, "Usage: %s -i [ID]\n", program_name);
}

int main(int argc, char **argv) {
  const char *program_name = argv[0];
  int ch;
  while ((ch = getopt(argc, argv, "i:")) != -1) {
    switch (ch) {
      case 'i':
        credential_id = optarg;
        break;
      case '?':
      default:
        usage(program_name);
        exit(1);
    }
  }
  argc -= optind;
  argv += optind;

  if (argc > 0 || !credential_id) {
    usage(program_name);
    exit(1);
  }

  // Initialize FIDO library.
	fido_init(0);
  iterate_devices(read_credential);
  return EXIT_SUCCESS;
}
