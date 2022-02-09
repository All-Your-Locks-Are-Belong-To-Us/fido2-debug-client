#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fido_util.h"
#include "gpio.h"
#include "crypto.h"

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
    printf("Content (%zu): %s\n", blob_len, blob_string);
    if (!strcmp(blob_content, "['door42']")) {
      printf("Access granted ✅.\n");
      blink_green();
    } else {
      printf("Access denied, invalid access rights.\n");
      blink_red();
    }
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

static void crypto_test() {
  uint8_t data[] = {'a', 'b', 'c'};
  uint8_t sig[] = {
    0x30, 0x35, 0x02, 0x18, 0x36, 0x7f, 0x33, 0x17, 0xbc, 0x73, 0xe6, 0x98,
    0xa8, 0x0b, 0xa7, 0xd9, 0xea, 0x84, 0xd3, 0x14, 0xd7, 0x88, 0xb6, 0xd1,
    0x1e, 0x03, 0x07, 0xa4, 0x02, 0x19, 0x00, 0xa8, 0x11, 0xd2, 0xf1, 0x31,
    0xb1, 0xb8, 0x90, 0xdd, 0x48, 0x52, 0xd5, 0x25, 0x98, 0xfc, 0xf1, 0xa4,
    0x05, 0x0e, 0x08, 0xa2, 0xc6, 0xc8, 0x1e
  };
  if (verify_ecdsa_signature(data, sizeof(data), sig, sizeof(sig))) {
    printf("Successfully verified signature.\n");
  }
}

int main(int argc, char **argv) {
  crypto_test();

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
