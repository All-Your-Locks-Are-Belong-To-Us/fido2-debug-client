/**
 * Small and crude library for manipulating GPIO pins on Raspi.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "gpio.h"

void gpio_init(uint8_t pin) {
  FILE* fd = fopen("/sys/class/gpio/export", "w");
  if (!fd) {
    perror("opening export");
    exit(-1);
  }
  fprintf(fd, "%d", pin);
  fclose(fd);

  char filename_buffer[64] = { 0 };
  sprintf(filename_buffer, "/sys/class/gpio/gpio%u/direction", pin);
  while (1) {
    // We need a loop here, because Linux takes its sweet time to create the corresponding
    // directories. So just loop over.
    fd = fopen(filename_buffer, "w");
    if (!fd) {
      continue;
    }
    fprintf(fd, "out");
    fclose(fd);
    break;
  }
}

void gpio_deinit(uint8_t pin) {
  FILE* fd = fopen("/sys/class/gpio/unexport", "w");
  fprintf(fd, "%d", pin);
  fclose(fd);
}

void gpio_set_state(uint8_t pin, uint8_t state) {
  char filename_buffer[64] = { 0 };
  sprintf(filename_buffer, "/sys/class/gpio/gpio%u/value", pin);
  FILE* fd = fopen(filename_buffer, "w");
  if (!fd) {
    perror("setting pin value");
    exit(-1);
  }
  fprintf(fd, "%u", state ? 1 : 0);
  fclose(fd);
}
