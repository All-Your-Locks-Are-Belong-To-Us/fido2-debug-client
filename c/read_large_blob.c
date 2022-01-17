#include <stdlib.h>
#include <stdio.h>
#include <fido.h>

#include "fido_util.h"

void read_large_blob(fido_dev_t *device)
{
  printf("Reading large blob...\n");

  unsigned char *cbor_array;
  size_t cbor_len;
  int ret = fido_dev_largeblob_get_array(device, &cbor_array, &cbor_len);

  if (ret != FIDO_OK)
  {
    fprintf(stderr, "Could not read large blob: %s\n", fido_strerr(ret));
    return;
  }
  
  printf("Large blob content:\n");
  for (size_t idx = 0; idx < cbor_len; ++idx) {
    printf("%02x", cbor_array[idx]);
  }
  printf("\n");

  free(cbor_array);
}

int main(void)
{
  // Initialize FIDO library.
  fido_init(0);

  iterate_devices(read_large_blob);

  return EXIT_SUCCESS;
}
