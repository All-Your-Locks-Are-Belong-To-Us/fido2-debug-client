# fido2-debug-client C

A little suite of FIDO2-tools based on [`libfido2`](https://github.com/Yubico/libfido2/) for debugging purposes.

## Dependencies

Tested on Debian bullseye, you first need to install the dependencies:

```bash
# Install base dependencies.
sudo apt install \
    build-essential \
    cmake \
    git \
    libcbor-dev \
    libpcsclite-dev \
    libssl-dev \
    libudev-dev \
    libz-dev \
    pkg-config \
    && true

# Compile & install libfido2.
git clone https://github.com/Yubico/libfido2.git
cd libfido2
mkdir build && cd build
cmake ..
make -j
sudo make install
```

## Compiling

To compile, you can simply run `make`.

## Contained tools

- [`create_credential`](./create_credential.c): Creates a new credential on the authenticator, outputting the `credentialId`.
- [`read_credential`](./read_credential.c): Reads a credential (assertion) by `credentialId`.
- [`read_device_info`](./read_device_info.c): Reads basic info about authenticator.
- [`read_large_blob`](./read_large_blob.c): Reads the large blob from the authenticator.
- [`reset`](./reset.c): Resets the authenticator.
- [`write_large_blob`](./write_large_blob.c): Writes a large blob to the authenticator.
