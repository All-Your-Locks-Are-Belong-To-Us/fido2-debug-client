#pragma once

#include <stdint.h>
#include <fido.h>

#define MAX_DEVICES   1

char *convert_to_hex(const uint8_t *bytes, size_t len);
uint8_t *convert_from_hex(const char *hex_string, size_t *len);

void get_device_info(fido_dev_t *device);
fido_dev_t *open_device(const fido_dev_info_t* device_info);
void iterate_devices(void (*device_function)(fido_dev_t *));
