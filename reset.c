#include <stdlib.h>
#include <stdio.h>

#include "fido_util.h"

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

  iterate_devices(reset_device);

  return EXIT_SUCCESS;
}
