# Xiaomi Mi / Nb BLE authentication
Many great apps stopped working because of protocol changes in the Xiaomi BLE communication. I found only very few apps that were able to perform pairing like in Mi Home, including two dashboard apps that were heavily obfuscated to prevent reverse engineering.

After spending many, many days and nights unraveling the new authentication protocol I have decided to release my work free of charge. My wish is that those apps and projects that went dead (and are getting review bombed...) soon come back to live.

Feel free to donate if you'd like to support my future research work:
[![](https://www.paypalobjects.com/de_DE/DE/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/donate/?hosted_button_id=G8FUS4LH2THES)

## Documentation
In order to understand the authentication process I captured BLE communication during the pairing process between Mi Home app and the target device. I have fully described the communication protocol and cryptography in the [Documentation](doc/).

## Python, Java and other libraries
For optimal platform support I provide both a [Python package](lib/python/) and a [Java library](lib/java/) for Mi authentication. You can find instructions on how to install and use these libraries in the respective folders.

If you want to use the Python library simply install it with `pip install miauth` - this also gives you access to the `miauth` command.

A __Swift__ port of this project is available here: https://github.com/nouun/miauth  
A __Rust__ port is available here: https://github.com/macbury/m365/tree/master/src

## Special thanks
This work would not have been possible without the following projects:

(Mi EC - 55ab)
* @atc1441 https://github.com/atc1441/ATC_MiThermometer
* @danielkucera https://github.com/danielkucera/mi-standardauth

(M365 - 55ab)
* @Informatic: https://github.com/Informatic/py9b

(M365 - 55aa)
* @CamiAlfa https://github.com/CamiAlfa/M365-BLE-PROTOCOL

(Nb - 5aa5)
* @nopbxlr @majsi https://github.com/scooterhacking/NinebotCrypto

## License
This branch comes without the Nb protocol/crypto library, which is AGPL licensed.
Since I'm no longer using any licensed material I'm free to choose a better suited license.

The Apache2 license applies to the code in this branch.

See LICENSE.md

## Disclaimer
I'm in no way affiliated with Xiaomi or any of their subsidiaries and products. This code has been provided for research purposes only.
