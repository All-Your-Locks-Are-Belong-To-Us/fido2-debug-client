from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.ctap2 import ClientPin, LargeBlobs
import sys


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev

for dev in enumerate_devices():
    client = Fido2Client(dev, "https://example.com")
    break

client_pin = ClientPin(client.ctap2)

if client.info.options.get("clientPin"):
    modify = input('Pin already set, do you want to modify it? (y/n): ')
    if modify != 'y':
        print('Pin unchanged.')
        sys.exit(0)
    print('Modifying pin...')
    old_pin = input('Please enter old pin: ')
    new_pin = input('Please enter new pin: ')
    client_pin.change_pin(old_pin, new_pin)
else:
    print('Pin not set, creating a new one...')
    new_pin = input('Please enter new pin: ')
    client_pin.set_pin(new_pin)
