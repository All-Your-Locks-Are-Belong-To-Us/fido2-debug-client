#pragma once

#include <stdint.h>

void gpio_init(uint8_t pin);
void gpio_deinit(uint8_t pin);
void gpio_set_state(uint8_t pin, uint8_t state);
