# Xiaomi Mi / Nb BLE client
Many great apps stopped working because of protocol changes in the Xiaomi BLE communication. I found only very few apps that were able to perform pairing like in Mi Home, including two silly dashboard apps that were heavily obfuscated to prevent reverse engineering.

After spending many, many days and nights unraveling the new authentication protocol I have decided to release my work free of charge. My wish is that those apps and projects that went dead (and are getting review bombed...) soon come back to live. If you appreciate and value my work, please [![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif)](https://www.paypal.com/donate/?hosted_button_id=PVK44XRRZWTKG)

## Description
In order to understand the authentication process I captured BLE communication during the pairing process between Mi Home app and the target device.
The communication is described in 'ble_security_proto.txt'. Further details including the cryptographic functions will be described in a separate post / file,
but for now you can always check the code.

## Installation
`pip install miauth`

Or clone this repository and run `pip install -e` inside the cloned directory.

## Usage examples
After installation, you will have access to the `miauth` command line interface (cli):

1. Register / pair with device via Mi EC protocol (generates 'mi_token' file):
`miauth <device_mac> --register`
1. Login and retrieve serial number and firmware version via Mi EC protocol:
`miauth -s -v <device_mac>`
1. Authenticate and retrieve serial number and firmware version via (legacy) Nb protocol:
`miauth --nb -s -v <device_mac>`

For a full list of the possible commands run `miauth -h`.

Note: Registering / pairing with devices unpairs the device from all other apps!
If you want to use your device with other apps after pairing, either reinstall or remove / re-add the device inside the app.

## Special thanks
This work would not have been possible without the following projects:

(Nb legacy protocol)
* @nopbxlr @majsi https://github.com/scooterhacking/NinebotCrypto
* @CamiAlfa https://github.com/CamiAlfa/M365-BLE-PROTOCOL

(Mi EC protocol)
* @danielkucera https://github.com/danielkucera/mi-standardauth
* @atc1441 https://github.com/atc1441/ATC_MiThermometer

## License
See LICENSE.md

## Disclaimer
I'm in no way affiliated with Xiaomi or any of their subsidiaries and products. This code has been provided for research purposes only.
