#include "fido_util.h"

#include <string.h>
#include <stdio.h>
 #include <ctype.h>

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

void get_device_info(fido_dev_t *device) {
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

  size_t options_len = fido_cbor_info_options_len(info);
  printf("Found the following options:\n");
  char **option_names = fido_cbor_info_options_name_ptr(info);
  const bool *option_values = fido_cbor_info_options_value_ptr(info);
  for (size_t option_idx = 0; option_idx < options_len; ++option_idx) {
    printf("- %s: %s\n", option_names[option_idx], option_values[option_idx] ? "true" : "false");
  }
  printf("----\n");

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
    if (device != NULL) {
      device_function(device);
      /*
      if (reset_authenticator) {
        reset_device(device);
        continue;
      }
      get_info(device);
      create_test_credential(device);
      */
      fido_dev_free(&device);
    }
  }

  cleanup:
  // Delete the list of device infos.
  fido_dev_info_free(&dev_list, MAX_DEVICES);

}
