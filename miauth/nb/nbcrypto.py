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

#     This class is my Python port of https://github.com/scooterhacking/NinebotCrypto
#     Huge thanks to the original authors for sharing their work!

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA1


class NbCrypto(object):
    FW_DATA = bytes.fromhex("97CFB802844143DE56002B3B34780A5D")

    def __init__(self):
        self.name = b''
        self.sha1_key = b''
        self.ble_data = None
        self.app_data = None
        self.it = 0

    def set_name(self, name):
        self.name = name
        self.sha1_key = NbCrypto.calc_sha1_key(self.name, NbCrypto.FW_DATA)

    def set_ble_data(self, ble_data):
        self.ble_data = ble_data
        self.sha1_key = NbCrypto.calc_sha1_key(self.name, self.ble_data)

    def set_app_data(self, app_data):
        self.app_data = app_data
        self.sha1_key = NbCrypto.calc_sha1_key(self.app_data, self.ble_data)

    def gen_aes_data(self):
        aes_data = bytearray(16)
        aes_data[0] = 1
        aes_data[1] = (self.it & 0xff000000) >> 24
        aes_data[2] = (self.it & 0x00ff0000) >> 16
        aes_data[3] = (self.it & 0x0000ff00) >> 8
        aes_data[4] = (self.it & 0x000000ff) >> 0
        aes_data[5:5 + 8] = self.ble_data[:8]
        aes_data[15] = 0
        return aes_data

    def encrypt(self, data):
        result = bytearray(152)
        result[:3] = data[:3]

        pl_len = len(data) - 3
        pl = bytearray(pl_len)
        pl[:] = data[3:3 + pl_len]

        if self.it == 0 or self.ble_data is None:
            crc = NbCrypto.crc_next(pl)
            enc = NbCrypto.crypto_next(pl, self.sha1_key)
            result[3:3 + pl_len] = enc[:]
            result[pl_len + 3] = 0
            result[pl_len + 4] = 0
            result[pl_len + 5] = crc[0]
            result[pl_len + 6] = crc[1]
            result[pl_len + 7] = 0
            result[pl_len + 8] = 0
            result = result[:pl_len + 9]
        else:
            self.it += 1

            aes_data = self.gen_aes_data()
            enc = NbCrypto.crypto_next(pl, self.sha1_key, aes_data)

            aes_data[0] = 0x59
            aes_data[15] = pl_len
            crc = NbCrypto.crc_next(data, self.sha1_key, aes_data)

            result[3:3 + pl_len] = enc[:]
            result[pl_len + 3] = crc[0]
            result[pl_len + 4] = crc[1]
            result[pl_len + 5] = crc[2]
            result[pl_len + 6] = crc[3]
            result[pl_len + 7] = (self.it & 0xff00) >> 8
            result[pl_len + 8] = (self.it & 0x00ff) >> 0
            result = result[:pl_len + 9]

        return result

    def decrypt(self, data):
        result = bytearray(len(data) - 6)
        result[:3] = data[:3]

        pl_len = len(data) - 9
        pl = bytearray(pl_len)
        pl[:] = data[3:3 + pl_len]

        # update it from response (last two bytes)
        self.it = (data[-2] << 8) + data[-1]

        if self.it == 0 or self.ble_data is None:
            dec = NbCrypto.crypto_next(pl, self.sha1_key)
            result[3:] = dec[:]
        else:
            aes_data = self.gen_aes_data()
            dec = NbCrypto.crypto_next(pl, self.sha1_key, aes_data)
            result[3:] = dec[:]

        return result

    @classmethod
    def crc_next(cls, data, sha1_key=None, aes_data=None):
        if sha1_key is None and aes_data is None:  # crc_first
            result = bytearray(2)

            crc = ~sum(data)
            result[0] = crc & 0xff
            result[1] = (crc >> 8) & 0xff

            return result

        aes_key = cls.aes_ecb_encrypt(aes_data, sha1_key)

        xor_data1 = bytearray(16)
        xor_data1[:3] = data[:3]
        xor_data2 = bytearray(16)
        xor_data2[:] = aes_key[:]

        xor_data = cls.xor(xor_data1, xor_data2, 16)
        aes_key = cls.aes_ecb_encrypt(xor_data, sha1_key)
        xor_data2[:] = aes_key[:]

        pl_len = len(data) - 3
        byte_idx = 3
        while pl_len > 0:
            tmp_len = pl_len if pl_len <= 16 else 16

            xor_data1 = bytearray(16)
            xor_data1[:tmp_len] = data[byte_idx:byte_idx + tmp_len]

            # like in crypto_next, but first xor then aes
            xor_data = cls.xor(xor_data1, xor_data2, 16)

            aes_key = cls.aes_ecb_encrypt(xor_data, sha1_key)
            xor_data2[:] = aes_key[:]

            pl_len -= tmp_len
            byte_idx += tmp_len

        # TODO: this is not nice
        aes_data[0] = 1
        aes_data[15] = 0

        aes_key = cls.aes_ecb_encrypt(aes_data, sha1_key)
        xor_data1[:4] = aes_key[:4]

        crc = cls.xor(xor_data1, xor_data2, 4)

        return crc

    @classmethod
    def crypto_next(cls, inp_data, sha1_key, aes_data=None):
        result = bytearray(len(inp_data))

        byte_idx = 0
        pl_len = len(inp_data)

        while pl_len > 0:
            tmp_len = pl_len if pl_len <= 16 else 16
            xor_data1 = bytearray(16)
            xor_data1[:tmp_len] = inp_data[byte_idx:byte_idx + tmp_len]

            if aes_data is None:
                aes_key = cls.aes_ecb_encrypt(cls.FW_DATA, sha1_key)
            else:
                aes_data[15] += 1
                aes_key = cls.aes_ecb_encrypt(aes_data, sha1_key)

            xor_data2 = bytearray(16)
            xor_data2[:] = aes_key[:]

            xor_data = cls.xor(xor_data1, xor_data2, 16)
            result[byte_idx:byte_idx + tmp_len] = xor_data[:tmp_len]

            pl_len -= tmp_len
            byte_idx += tmp_len

        return result

    @staticmethod
    def calc_sha1_key(b1, b2):
        data = bytearray(32)
        data[:16] = b1
        data[16:] = b2

        sha = Hash(SHA1())
        sha.update(data)
        h = sha.finalize()[:16]
        assert len(h) == 16
        return h

    @staticmethod
    def aes_ecb_encrypt(data, key):
        aes = Cipher(
            algorithms.AES(key),
            modes.ECB(),
        ).encryptor()
        ct = aes.update(data) + aes.finalize()
        return ct

    @staticmethod
    def xor(d1, d2, size):
        result = bytearray(size)
        for i in range(size):
            result[i] = d1[i] ^ d2[i]
        return result
