CFLAGS = -I/usr/local/Cellar/openssl@1.1/1.1.1m/include -I /usr/local/Cellar/libfido2/1.9.0_1/include/ -g
LDFLAGS = -L /usr/local/Cellar/libfido2/1.9.0_1/lib -L /usr/local/Cellar/openssl@1.1/1.1.1m/lib
LDLIBS = -l fido2 -lssl

TARGETS = reset create_credential read_credential

.PHONY: all
all: $(TARGETS)

reset: fido_util.o
create_credential: fido_util.o
read_credential: fido_util.o

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

-include *.d

.PHONY: clean
clean:
	$(RM) $(TARGETS)
