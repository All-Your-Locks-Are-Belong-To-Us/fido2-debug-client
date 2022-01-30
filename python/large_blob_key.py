from fido2.hid import CtapHidDevice
from fido2.ctap2 import ClientPin, LargeBlobs
from fido2.client import Fido2Client
from fido2.server import Fido2Server
import sys
import random


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev

# Locate a device
for dev in enumerate_devices():
    client = Fido2Client(dev, "https://example.com")
    if "largeBlobKey" in client.info.extensions and client.info.options.get("largeBlobs"):
        break
else:
    print("No Authenticator with the largeBlobKey extension found!")
    sys.exit(1)

client_pin = ClientPin(client.ctap2)
pin = None
uv = "discouraged"
token = None

# Prefer UV token if supported
if client.info.options.get("pinUvAuthToken") and client.info.options.get("uv"):
    uv = "preferred"
    print("Authenticator supports UV token")
elif client.info.options.get("clientPin"):
    # Prompt for PIN if needed
    pin = input("Please enter PIN: ")
else:
    print("PIN not set, won't use")

server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")

user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key=True,
    user_verification=uv,
    authenticator_attachment="cross-platform",
)

# Enable largeBlobKey
options = create_options["publicKey"]
options.extensions = {"largeBlobKey": True}

# Create a credential
print("Creating a new credential...")
print("\nTouch your authenticator device now...\n")

result = client.make_credential(options, pin=pin)
key = result.attestation_object.large_blob_key

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)
credentials = [auth_data.credential_data]

print("New credential created!")
print("Large Blob Key:", key)

if pin:
    token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.LARGE_BLOB_WRITE)

large_blobs = LargeBlobs(client.ctap2, client_pin.protocol, token)

# Write a large blob
print("Writing a large blob...")
large_blob_data = b"Here is some data to store!"
# large_blob_data = random.randbytes(1024)
large_blobs.put_blob(key, large_blob_data)

# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin()

# Enable largeBlobKey
options = request_options["publicKey"]
options.extensions = {"largeBlobKey": True}

# Authenticate the credential
print("Getting an assertion to receive large blob key...")
print("\nTouch your authenticator device now...\n")

selection = client.get_assertion(options, pin=pin)
# Only one cred in allowCredentials, only one response.
assertion = selection.get_assertions()[0]

print(f"Received large blob key: {assertion.large_blob_key}")

# Get a fresh PIN token
if pin:
    token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.LARGE_BLOB_WRITE)
large_blobs = LargeBlobs(client.ctap2, client_pin.protocol, token)

key = assertion.large_blob_key
blob = large_blobs.get_blob(key)
print(f"Read blob {blob}")

blob = large_blobs.read_blob_array()
print(f"Complete blob array: {blob}")

# Clean up
# print(f"Removing large blob for key: {key}")
# large_blobs.delete_blob(key)
