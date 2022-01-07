#include <stdlib.h>
#include <stdio.h>

#include "fido_util.h"

void read_device_info(fido_dev_t *device) {
  printf("Reading device info...\n");
  get_device_info(device);
}

int main(void) {
  // Initialize FIDO library.
  fido_init(0);

  iterate_devices(read_device_info);

  return EXIT_SUCCESS;
}
