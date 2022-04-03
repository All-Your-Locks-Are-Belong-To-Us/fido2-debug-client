#include "fido_util.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define FIDO_INTERNAL

char * convert_to_hex(const uint8_t *bytes, size_t len) {
  const size_t required_string_length = len * 2 + 1;
  char *hex_string = (char *)malloc(required_string_length);
  memset(hex_string, 0x0, required_string_length);
  for (size_t idx = 0; idx < len; ++idx) {
    snprintf(hex_string + 2*idx, 3, "%02X", bytes[idx]);
  }
  return hex_string;
}

static inline uint8_t hex_nibble(const char *hex_string) {
  const char current_char = toupper(*hex_string);
  if (current_char >= '0' && current_char <= '9') {
    return current_char - '0';
  } else if (current_char >= 'A' && current_char <= 'F') {
    return current_char - 'A' + 10;
  }
  return 0;
}

static inline uint8_t hex_byte(const char *hex_string) {
  if (*(hex_string + 1) == '\0') {
    return hex_nibble(hex_string);
  }
  return hex_nibble(hex_string) << 4 | hex_nibble(hex_string + 1);
}

uint8_t *convert_from_hex(const char *hex_string, size_t *len) {
  ssize_t string_len = strlen(hex_string);
  size_t buffer_len = (string_len / 2) + (string_len & 0x1);
  if (len != NULL) {
    *len = buffer_len;
  }
  uint8_t *hex_buffer = (uint8_t*)malloc(buffer_len);
  if (!hex_buffer) {
    return NULL;
  }
  uint8_t *hex_buffer_current = hex_buffer;
  uint8_t byte;
  while (string_len > 0) {
    *(hex_buffer_current++) = hex_byte(hex_string);
    string_len -= 2;
    hex_string += 2;
  }
  return hex_buffer;
}

static const char *tree_symbol(const size_t items_left) {
  return items_left > 0 ? "├" : "└";
}

void get_device_info(fido_dev_t *device) {
  printf("\n");
  fido_cbor_info_t *info = fido_cbor_info_new();
  if (!info) {
    perror("fido_cbor_info_new");
    return;
  }

  int ret = fido_dev_get_cbor_info(device, info);
  if (ret != FIDO_OK) {
    fprintf(stderr, "Error getting info %s.\n", fido_strerr(ret));
    goto info_cleanup;
  }

  printf("Authenticator\n");

  // AAGUID
  const size_t aaguid_len = fido_cbor_info_aaguid_len(info);
  const uint8_t *aaguid_ptr = fido_cbor_info_aaguid_ptr(info);
  if (aaguid_ptr != NULL) {
    char* aaguid_string = convert_to_hex(aaguid_ptr, aaguid_len);
    printf("├── AAGUID: %s\n", aaguid_string);
    free(aaguid_string);
  } else {
    printf("├── AAGUID: NULL\n");
  }

  // Versions
  size_t num_versions = fido_cbor_info_versions_len(info);
  char **versions = fido_cbor_info_versions_ptr(info);
  printf("├── versions (%zu)\n", num_versions);
  while(num_versions-- > 0) {
    char *version = *(versions++);
    printf("│   %s── %s\n", tree_symbol(num_versions), version);
  }

  // Transports
  size_t num_transports = fido_cbor_info_transports_len(info);
  char **transports_ptr = fido_cbor_info_transports_ptr(info);
  printf("├── transports (%zu)\n", num_transports);
  while (num_transports-- > 0) {
    const char *transport = *(transports_ptr++);
    printf("│   %s── %s\n", tree_symbol(num_transports), transport);
  }

  // PIN Protocols
  size_t num_pin_protocols = fido_cbor_info_protocols_len(info);
  const uint8_t *pin_protocols = fido_cbor_info_protocols_ptr(info);
  printf("├── pin protocols (%zu)\n", num_pin_protocols);
  while(num_pin_protocols-- > 0) {
    uint8_t pin_protocol = *(pin_protocols++);
    printf("│   %s── %d\n", tree_symbol(num_pin_protocols), pin_protocol);
  }

  // Options
  const size_t num_options = fido_cbor_info_options_len(info);
  char **option_names = fido_cbor_info_options_name_ptr(info);
  printf("├── options (%zu)\n", num_options);
  const bool *option_values = fido_cbor_info_options_value_ptr(info);
  for (size_t option_idx = 0; option_idx < num_options; ++option_idx) {
    printf("│   %s── %s: %s\n", tree_symbol(num_options - option_idx - 1), option_names[option_idx], option_values[option_idx] ? "true" : "false");
  }

  // Extensions
  size_t extensions_len = fido_cbor_info_extensions_len(info);
  char **extensions_ptr = fido_cbor_info_extensions_ptr(info);
  printf("├── extensions (%zu)\n", extensions_len);
  while(extensions_len-- > 0) {
    const char *extension = *(extensions_ptr++);
    printf("│   %s── %s\n", tree_symbol(extensions_len), extension);
  }

  // Algorithms
  const size_t num_algorithms = fido_cbor_info_algorithm_count(info);
  printf("├── algorithms (%zu)\n", num_algorithms);
  for (size_t algorithm_idx = 0; algorithm_idx < num_algorithms; ++algorithm_idx) {
    const char *algorithm_type = fido_cbor_info_algorithm_type(info, algorithm_idx);
    int algorithm_cose = fido_cbor_info_algorithm_cose(info, algorithm_idx);
    printf("│   %s── %s (%d)\n", tree_symbol(num_algorithms - algorithm_idx - 1), algorithm_type, algorithm_cose);
  }

  printf("├── maxMsgSize: %llu\n", fido_cbor_info_maxmsgsiz(info));
  printf("├── maxCredBlobLength: %llu\n", fido_cbor_info_maxcredbloblen(info));
  printf("├── maxCredentialCountInList: %llu\n", fido_cbor_info_maxcredcntlst(info));
  printf("├── maxCredentialIdLength: %llu\n", fido_cbor_info_maxcredidlen(info));
  printf("└── firmware version: %llu\n", fido_cbor_info_fwversion(info));


  info_cleanup:
  fido_cbor_info_free(&info);
}

fido_dev_t *open_device(const fido_dev_info_t* device_info) {
  printf("Found authenticator %s at path %s.\n", fido_dev_info_product_string(device_info), fido_dev_info_path(device_info));

  // Allocate a new device for opening.
  fido_dev_t *device = fido_dev_new();
  if (device == NULL) {
    perror("fido_dev_new");
    return NULL;
  }

  int ret = fido_dev_open(device, fido_dev_info_path(device_info));
  if (ret != FIDO_OK) {
    fprintf(stderr, "Error opening FIDO2 device: %s\n", fido_strerr(ret));
    fido_dev_free(&device);
    return NULL;
  }

  if (!fido_dev_is_fido2(device)) {
    fprintf(stderr, "The device is no FIDO2 device.\n");
    fido_dev_free(&device);
  }
  return device;
}

void iterate_devices(void (*device_function)(fido_dev_t *)) {
  // Allocate a new list for FIDO devices.
  fido_dev_info_t *dev_list = fido_dev_info_new(MAX_DEVICES);
  if (dev_list == NULL) {
    perror("fido_dev_info_new");
    exit(EXIT_FAILURE);
  }

  size_t nr_found_devices;
  fido_dev_info_manifest(dev_list, MAX_DEVICES, &nr_found_devices);

  if (nr_found_devices == 0) {
    fprintf(stderr, "No FIDO devices found. Exiting.\n");
    goto cleanup;
  }

  // Iterate over all devices.
  for (size_t device_idx = 0; device_idx < nr_found_devices; ++device_idx) {
    const fido_dev_info_t *info = fido_dev_info_ptr(dev_list, device_idx);
    fido_dev_t * device = open_device(info);
    if (!device) {
      continue;
    }

    // Disable timeout for easier debugging.
    const int ret = fido_dev_set_timeout(device, -1);
    if (ret != FIDO_OK) {
      fprintf(stderr, "Could not set timeout: %s\n", fido_strerr(ret));
    }

    device_function(device);
    fido_dev_close(device);
    fido_dev_free(&device);
  }

  cleanup:
  // Delete the list of device infos.
  fido_dev_info_free(&dev_list, MAX_DEVICES);
}
