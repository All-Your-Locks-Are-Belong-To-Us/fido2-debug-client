#include <stdlib.h>
#include <stdio.h>
#include <fido.h>

#include "fido_util.h"

void write_large_blob(fido_dev_t *device)
{
  printf("Writing large blob...\n");

  unsigned char cbor_array[] = { 0x82, 0x1, 0x83, 0x2, 0x3, 0x4 };
  int ret = fido_dev_largeblob_set_array(device, cbor_array, sizeof(cbor_array), NULL);

  if (ret != FIDO_OK)
  {
    fprintf(stderr, "Could not write large blob: %s\n", fido_strerr(ret));
  }
}

int main(void)
{
  // Initialize FIDO library.
  fido_init(0);

  iterate_devices(write_large_blob);

  return EXIT_SUCCESS;
}
