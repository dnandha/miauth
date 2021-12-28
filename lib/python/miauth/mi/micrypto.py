#
#     MiAuth - Authenticate and interact with Xiaomi devices over BLE
#     Copyright (C) 2021  Daljeet Nandha
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as
#     published by the Free Software Foundation, either version 3 of the
#     License, or (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.
#
#     You should have received a copy of the GNU Affero General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

#     Huge thanks to Aaron Christophel (Atc1441) and Daniel Kucera!
#     I have adapted some function and variable declarations from their respective works:
#           https://github.com/danielkucera/mi-standardauth/blob/master/provision.py
#           https://github.com/atc1441/atc1441.github.io/blob/master/TelinkFlasher.html

import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from miauth.util import crc16, int_to_bytes


class MiCrypto(object):
    @staticmethod
    def gen_rand_key():
        return secrets.token_bytes(16)

    @staticmethod
    def bytes_to_pub_key(data):
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b'\x04' + data)

    @staticmethod
    def pub_key_to_bytes(key):
        return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]

    @staticmethod
    def gen_keypair():
        priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pub_key = priv_key.public_key()
        return priv_key, pub_key

    @staticmethod
    def val_to_private_key(val):
        return ec.derive_private_key(val, ec.SECP256R1())

    @staticmethod
    def private_key_to_val(key):
        return key.private_numbers().private_value

    @staticmethod
    def generate_secret(private_key, public_key):
        return private_key.exchange(ec.ECDH(), public_key)

    @staticmethod
    def derive_key(shared_key, salt=None):
        info = b"mible-login-info"
        if salt is None:
            info = b"mible-setup-info"

        return HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(shared_key)

    @staticmethod
    def hash(derived_key, data):
        hmac = HMAC(derived_key, algorithm=hashes.SHA256())
        hmac.update(data)
        return hmac.finalize()

    @staticmethod
    def encrypt_did(key, did):
        aes_ccm = AESCCM(key, tag_length=4)
        nonce = bytes([16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27])
        did = did
        aad = b"devID"

        return aes_ccm.encrypt(nonce, did, aad)

    @staticmethod
    def encrypt_uart(key, iv, msg, it=0, rand=secrets.token_bytes(4)):
        msg = msg[2:]  # ditch header

        size = msg[:1]
        data = msg[1:]
        data += rand  # add four random bytes to data

        it = int_to_bytes(it)  # encode iterator to four bytes
        nonce = iv + bytes([0] * 4) + it

        aes_ccm = AESCCM(key, tag_length=4)
        ct = aes_ccm.encrypt(nonce, data, None)

        header = b'\x55\xab'  # new header
        data = size + it[:2] + ct  # new data
        crc = crc16(data)  # new checksum

        return header + data + crc

    @staticmethod
    def decrypt_uart(key, iv, msg):
        header = msg[:2]
        if header != b'\x55\xab':
            raise Exception("Invalid header.")

        it = msg[3:5]
        ct = msg[5:-2]

        nonce = iv + bytes([0] * 4) + it + bytes([0] * 2)

        aes_ccm = AESCCM(key, tag_length=4)
        return aes_ccm.decrypt(nonce, ct, None)
