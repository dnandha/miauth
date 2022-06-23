# Xiaomi Mi / Nb BLE authentication
Many great apps stopped working because of protocol changes in the Xiaomi BLE communication. I found only very few apps that were able to perform pairing like in Mi Home, including two dashboard apps that were heavily obfuscated to prevent reverse engineering.

After spending many, many days and nights unraveling the new authentication protocol I have decided to release my work free of charge. My wish is that those apps and projects that went dead (and are getting review bombed...) soon come back to live.

If you want to support my research work, please [![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif)](https://www.paypal.com/donate/?hosted_button_id=PVK44XRRZWTKG)

## Documentation
In order to understand the authentication process I captured BLE communication during the pairing process between Mi Home app and the target device. I have fully described the communication protocol and cryptography in the [Documentation](doc/).

## Python and Java libraries
For optimal platform support I provide both a [Python package](lib/python/) and a [Java library](lib/java/) for Mi authentication. You can find instructions on how to install and use these libraries in the respective folders.

If you want to use the Python library simply install it with `pip install miauth` - this also gives you access to the `miauth` command.

## Special thanks
This work would not have been possible without the following projects:

(Nb legacy protocol: 5aa5)
* @nopbxlr @majsi https://github.com/scooterhacking/NinebotCrypto

(M365 protocol: 55aa)
* @CamiAlfa https://github.com/CamiAlfa/M365-BLE-PROTOCOL

(M365 protocol: 55ab)
* @Informatic: https://github.com/Informatic/py9b

(Mi EC protocol: 55ab)
* @atc1441 https://github.com/atc1441/ATC_MiThermometer
* @danielkucera https://github.com/danielkucera/mi-standardauth

## License
This branch comes without the Nb protocol/crypto library, which is AGPL licensed.
Since I'm no longer using any licensed material I'm free to choose a better suited license.

The Apache2 license applies to the code in this branch.

See LICENSE.md

## Disclaimer
I'm in no way affiliated with Xiaomi or any of their subsidiaries and products. This code has been provided for research purposes only.
