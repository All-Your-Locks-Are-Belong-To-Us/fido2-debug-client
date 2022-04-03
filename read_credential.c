#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fido_util.h"

#ifndef RPID
#define RPID "localhost"
#endif

static char *credential_id = NULL;
static char *large_blob_content_file = NULL;
static bool read_large_blob_content = false;

static void read_credential(fido_dev_t *device){
  // Create an assertion.
  fido_assert_t *assert = fido_assert_new();
  if (!assert) {
    fprintf(stderr, "Could not allocate assertion.\n");
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

  if (credential_id) {
    // A credential ID was passed, only allow that one.
    size_t id_len;
    uint8_t *hex_id = convert_from_hex(credential_id, &id_len);
    if (id_len == 0) {
      fprintf(stderr, "Could not parse HEX from credential id.\n");
      return;
    }

    printf("Reading credential with id %s\n", credential_id);

    // Set which credentials are allowed.
    ret = fido_assert_allow_cred(assert, hex_id, id_len);
    if (ret != FIDO_OK) {
      fprintf(stderr, "Could not set allowed credentials: %s\n", fido_strerr(ret));
      free(hex_id);
      goto cleanup_read_credential;
    }
    free(hex_id);
  }

  // Force user presence.
  ret = fido_assert_set_up(assert, FIDO_OPT_FALSE);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Could not set user presence: %s\n", fido_strerr(ret));
    goto cleanup_read_credential;
  }

  if (read_large_blob_content || large_blob_content_file) {
  ret = fido_assert_set_extensions(assert, FIDO_EXT_LARGEBLOB_KEY);
    if (ret != FIDO_OK) {
      fprintf(stderr, "Could not enable largeBlobKey extension: %s\n", fido_strerr(ret));
      goto cleanup_read_credential;
    }
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

  if (read_large_blob_content || large_blob_content_file) {
    const unsigned char *large_blob_key_ptr = fido_assert_largeblob_key_ptr(assert, 0);
    if (large_blob_key_ptr) {
      const size_t large_blob_key_len = fido_assert_largeblob_key_len(assert, 0);

      // Print the key.
      char *large_blob_key_str = convert_to_hex(large_blob_key_ptr, large_blob_key_len);
      printf("largeBlobKey: %s\n", large_blob_key_str);
      free(large_blob_key_str);

      // Write content of large blob.
      if (large_blob_content_file) {
        char blob_data[1024];
        memset(blob_data, 0, sizeof(blob_data));
        FILE *fil = fopen(large_blob_content_file, "r");
        if (fil == NULL) {
          perror("fopen large_blob_content_file");
          goto cleanup_read_credential;
        }
        fgets(blob_data, sizeof(blob_data) - 1, fil);
        fclose(fil);

        const size_t content_len = strlen(blob_data);
        ret = fido_dev_largeblob_set(device, large_blob_key_ptr, large_blob_key_len, blob_data, content_len, NULL);
        if (ret != FIDO_OK) {
          fprintf(stderr, "Could not set per credential large blob content: %s.\n", fido_strerr(ret));
          goto cleanup_read_credential;
        }
      }

      // And get the content.
      if (read_large_blob_content) {
        uint8_t *blob_content = NULL;
        size_t blob_len;
        ret = fido_dev_largeblob_get(device, large_blob_key_ptr, large_blob_key_len, &blob_content, &blob_len);
        if (ret != FIDO_OK || !blob_content) {
          fprintf(stderr, "Could not decrypt large blob content: %s.\n", fido_strerr(ret));
          free(blob_content);
          goto cleanup_read_credential;
        }

        printf("Got %zu bytes of large blob:\n", blob_len);
        char *large_blob_content_str = convert_to_hex(blob_content, blob_len);
        printf("%s\n", large_blob_content_str);
        free(large_blob_content_str);

        free(blob_content);
      }
    }
  }

  cleanup_read_credential:
  fido_assert_free(&assert);
}

static void usage(const char *program_name) {
  fprintf(stderr, "Usage: %s [-i credential_id] [-l] [-w large_blob_content_file]\n", program_name);
}

int main(int argc, char **argv) {
  const char *program_name = argv[0];
  int ch;
  while ((ch = getopt(argc, argv, "i:lw:")) != -1) {
    switch (ch) {
      case 'i':
        credential_id = optarg;
        break;
      case 'l':
        read_large_blob_content = true;
        break;
      case 'w':
        large_blob_content_file = optarg;
        break;
      case '?':
      default:
        usage(program_name);
        exit(1);
    }
  }
  argc -= optind;
  argv += optind;

  // Initialize FIDO library.
  fido_init(0);
  iterate_devices(read_credential);
  return EXIT_SUCCESS;
}
