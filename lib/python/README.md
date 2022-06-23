# Xiaomi Mi / Nb BLE - Python Lib + CLI

## Installation
`pip install miauth`

Or clone this repository and run `pip install -e` inside the cloned directory.

### Running tests
`python -m pytest` or `tox` in project main directory.

## Usage examples
After installation, you will have access to the `miauth` command line interface (cli):

1. Register / pair with device via Mi EC protocol (generates 'mi_token' file):
`miauth <device_mac> --register`
1. Login and retrieve serial number and firmware version via Mi EC protocol:
`miauth -s -v <device_mac>`
1. Retrieve serial number and firmware version via M365 protocol:
`miauth --m365 -s -v <device_mac>`
1. Authenticate and retrieve serial number and firmware version via Nb protocol:
`miauth --nb -s -v <device_mac>`

For a full list of the possible commands run `miauth -h`.

Note: Registering / pairing with devices unpairs the device from all other apps!
If you want to use your device with other apps after pairing, either reinstall or remove / re-add the device inside the app.

## License
See LICENSE.md

## Disclaimer
I'm in no way affiliated with Xiaomi or any of their subsidiaries and products. This code has been provided for research purposes only.
