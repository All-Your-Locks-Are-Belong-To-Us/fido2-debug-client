#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fido_util.h"
#include "gpio.h"
#include "crypto.h"
#include "cbor_decode.h"

#ifndef GREEN_PIN
#define GREEN_PIN 26
#endif

#ifndef RED_PIN
#define RED_PIN 6
#endif

#ifndef RPID
#define RPID "localhost"
#endif

#define BLINK_MS 50

static char *credential_id = NULL;
static volatile bool should_exit = false;

static void leds_off() {
  gpio_set_state(GREEN_PIN, 0);
  gpio_set_state(RED_PIN, 0);
}

static void blink_green() {
  gpio_set_state(GREEN_PIN, 1);
  gpio_set_state(RED_PIN, 0);
  usleep(BLINK_MS * 1000);
  leds_off();
}

static void blink_red() {
  gpio_set_state(GREEN_PIN, 0);
  gpio_set_state(RED_PIN, 1);
  usleep(BLINK_MS * 1000);
  leds_off();
}

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
  printf("RP ID is %s\n", RPID);
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

  // Do not force user presence (otherwise, NFC won't work).
  ret = fido_assert_set_up(assert, FIDO_OPT_FALSE);
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
    printf("Access denied.\n");
    blink_red();
    goto cleanup_read_credential;
  }

  // Get user and stuff from assertion.
  printf("User: %s (display name: %s)\n", fido_assert_user_name(assert, 0), fido_assert_user_display_name(assert, 0));
  printf("Sigcount %d and user_id len %zu\n", fido_assert_sigcount(assert, 0), fido_assert_user_id_len(assert, 0));

  const unsigned char *large_blob_key_ptr = fido_assert_largeblob_key_ptr(assert, 0);
  if (large_blob_key_ptr) {
    const size_t large_blob_key_len = fido_assert_largeblob_key_len(assert, 0);

    // Print the key.
    char *large_blob_key_str = convert_to_hex(large_blob_key_ptr, large_blob_key_len);
    printf("largeBlobKey: %s\n", large_blob_key_str);
    free(large_blob_key_str);

    uint8_t *blob_content = NULL;
    size_t blob_len = 0;
    ret = fido_dev_largeblob_get(device, large_blob_key_ptr, large_blob_key_len, &blob_content, &blob_len);
    if (ret != FIDO_OK || !blob_content) {
      fprintf(stderr, "Could not decrypt large blob content: %s.\n", fido_strerr(ret));
      printf("Access denied, no access data.\n");
      blink_red();
      free(blob_content);
      goto cleanup_read_credential;
    }

    char *blob_string = (char *)malloc(blob_len + 1);
    memset(blob_string, 0, blob_len + 1);
    memcpy(blob_string, blob_content, blob_len);
    // printf("Content (%zu): %s\n", blob_len, blob_string);

    uint8_t *access_rights;
    size_t access_rights_len;
    uint8_t *credential_pub_key;
    size_t credential_pub_key_len;
    uint8_t *signature;
    size_t signature_len;
    const bool decoded_successfully = decode_cbor_access_rights(blob_content, blob_len, &access_rights, &access_rights_len, &credential_pub_key, &credential_pub_key_len, &signature, &signature_len);

    if (decoded_successfully) {
      // Still need to verify the signature.
      uint8_t *data_buf = (uint8_t*)malloc(access_rights_len + credential_pub_key_len);
      if (!data_buf); // TODO
      memcpy(data_buf, access_rights, access_rights_len);
      memcpy(data_buf + access_rights_len, credential_pub_key, credential_pub_key_len);
      if (verify_ecdsa_signature(data_buf, access_rights_len + credential_pub_key_len, signature, signature_len)) {
	// Last step: The public key of the credential must match the signed value to prevent key cloning attacks.
        if (verify_fido_assertion(assert, credential_pub_key, credential_pub_key_len)) {
          printf("Access granted ✅.\n");
          blink_green();
	} else {
          printf("Access denied, public key mismatch.\n");
          blink_red();
	}
      } else {
      	printf("Access denied, signature incorrect.\n");
	blink_red();
      }
    } else {
      printf("Access denied, could not decode access rights.\n");
      blink_red();
    }

    /*if (!strcmp(blob_content, "['door42']")) {
      printf("Access granted ✅.\n");
      blink_green();
    } else {
      printf("Access denied, invalid access rights.\n");
      blink_red();
    }*/
    free(blob_string);
    free(blob_content);
  } else {
    printf("Access denied, no large blob key.\n");
    blink_red();
  }

  cleanup_read_credential:
  printf("\n");
  fido_assert_free(&assert);
}

static void sigint_handler(int sig) {
  fprintf(stderr, "Requesting exit...\n");
  should_exit = true;
}

static void usage(const char *program_name) {
  fprintf(stderr, "Usage: %s [-i credential_id] [-l] [-w large_blob_content_file]\n", program_name);
}

int main(int argc, char **argv) {
  gpio_init(GREEN_PIN);
  gpio_init(RED_PIN);

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

  // Wire up SIGINT handler.
  if (signal(SIGINT, sigint_handler) == SIG_ERR) {
    perror("signal SIGINT");
    exit(1);
  }

  // Initialize FIDO library.
  fido_init(0);
  while (!should_exit) {
    iterate_devices(read_credential);
  }

  gpio_deinit(GREEN_PIN);
  gpio_deinit(RED_PIN);
  return EXIT_SUCCESS;
}
