from fido2.hid import CtapHidDevice
from fido2.ctap2 import ClientPin, LargeBlobs
from fido2.client import Fido2Client
from fido2.server import Fido2Server
import sys


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
large_blobs = LargeBlobs(client.ctap2, client_pin.protocol, None)


server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")

user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key=True,
    authenticator_attachment="cross-platform",
)

# Enable largeBlobKey
options = create_options["publicKey"]
options.extensions = {"largeBlobKey": True}

# Create a credential
print("Creating a new credential...")
print("\nTouch your authenticator device now...\n")

result = client.make_credential(options)
key = result.attestation_object.large_blob_key

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)
credentials = [auth_data.credential_data]

print("New credential created!")
print("Large Blob Key:", key)

# Write a large blob
print("Writing a large blob...")
large_blobs.put_blob(key, b"Here is some data to store!")

# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin()

# Enable largeBlobKey
options = request_options["publicKey"]
options.extensions = {"largeBlobKey": True}

# Authenticate the credential
print("Getting an assertion to receive large blob key...")
print("\nTouch your authenticator device now...\n")

selection = client.get_assertion(options)
# Only one cred in allowCredentials, only one response.
assertion = selection.get_assertions()[0]

print(f"Received large blob key: {assertion.large_blob_key}")

key = assertion.large_blob_key
large_blobs = LargeBlobs(client.ctap2, client_pin.protocol, None)
blob = large_blobs.get_blob(key)
print(f"Read blob {blob}")

blob = large_blobs.read_blob_array()
print(f"Complete blob array: {blob}")

# Clean up
print(f"Removing large blob for key: {key}")
large_blobs.delete_blob(key)
