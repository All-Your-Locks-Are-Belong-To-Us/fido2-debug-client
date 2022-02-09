UNAME := $(shell uname)

# Relying Party ID
RPID := wau.felixgohla.de

CFLAGS = -g -DRPID='"${RPID}"'
ifeq ($(UNAME), Darwin)
CC = gcc-11
BREW_PREFIX := $(shell brew --prefix)
CFLAGS += -I$(BREW_PREFIX)/opt/openssl@3/include -I$(BREW_PREFIX)/include
LDFLAGS = -L$(BREW_PREFIX)/opt/openssl@3/lib -L./libfido2/build/src -Wl,-rpath libfido2/build/src
else
endif
LDLIBS = -lfido2 -lssl -lcrypto

TARGETS = reset create_credential read_credential read_device_info read_large_blob write_large_blob lock_simulator

.PHONY: all
all: $(TARGETS)

reset: fido_util.o
create_credential: fido_util.o
read_credential: fido_util.o
read_device_info: fido_util.o
read_large_blob: fido_util.o
write_large_blob: fido_util.o
lock_simulator: fido_util.o gpio.o crypto.o

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

-include *.d

.PHONY: clean
clean:
	$(RM) -r $(TARGETS) *.o *.d *dSYM
