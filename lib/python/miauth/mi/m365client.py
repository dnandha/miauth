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
#
#     Huge thanks and credits to Camilo (CamiAlfa) for his work on 55aa:
#       https://github.com/CamiAlfa/M365-BLE-PROTOCOL
#       https://github.com/CamiAlfa/M365-BLE-PROTOCOL/blob/master/protocolo
#     Huge thanks and credits to Piotr Dobrowolski, adapted 55ab from this work:
#       https://github.com/Informatic/py9b
#       https://github.com/Informatic/py9b/issues/2#issuecomment-549683873
#       https://github.com/CamiAlfa/M365-BLE-PROTOCOL/issues/7#issuecomment-546872603

from bluepy import btle

from miauth.mi.micommand import MiCommand
from miauth.ble.uuid import UUID
from miauth.ble.base import BLEBase
from miauth.util import crc16


class M365Client(btle.DefaultDelegate):
    def __init__(self, ble: BLEBase, debug=False):
        self.ble = ble
        self.debug = debug

        self.ble.set_handler(self.main_handler)

        self.key = None

        # buffer for receive handler
        self.receive_frames = 0
        self.received_data = b''

        # counter for sent uart commands
        self.uart_it = 0

    def main_handler(self, data):
        if len(data) == 0:
            return
        self.received_data += data

    def connect(self):
        self.ble.connect()

    def disconnect(self):
        self.ble.disconnect()

    def reset(self):
        self.ble.disconnect()
        self.__init__(self.p, self.mac, debug=self.debug)

    def recover_key(self):
        if self.ble.has_channel(UUID.KEY):
            print("found old 55ab encryption -> recovering key")
            self.key = self.ble.read(UUID.KEY)
            self.key += self.comm("55aa0322015020")[9:]
            if self.debug:
                print("key:", self.key.hex(" "))

    def comm(self, cmd):
        if type(cmd) not in [bytearray, bytes]:
            cmd = bytes.fromhex(cmd)

        if cmd[:2] != b'\x55\xaa':
            if cmd[:2] == b'\x5a\xa5':
                raise Exception("Command must start with 55 AA (M365 PROTOCOl)!\
                                You sent a Nb command, try Nb pairing instead.")
            else:
                raise Exception("Command must start with 55 AA (M365 PROTOCOl)!")

        self.received_data = b''

        if self.key:
            len_ = cmd[2:3]
            cmd = b'\x55\xab' + len_ + self.crypt(cmd[3:] + b'\x00\x00\x00\x00')
        res = cmd + crc16(cmd[2:])  # new checksum
        self.ble.write_chunked(UUID.TX, res)
        self.uart_it += 1

        self.ble.wait_notify()

        if not self.received_data:
            print("No answer received")
            return bytes()

        if self.debug:
            print("received:", self.received_data.hex(" "))
        res = self.received_data
        if crc16(res[2:-2]) != res[-2:]:
            raise Exception("Checksum mismatch in response")

        if self.key:
            res = self.crypt(res[3:])[:-4]

        if self.debug:
            print("response:", res.hex(" "))
        return res[3:-2]

    def crypt(self, data):
        k = self.key
        return bytearray([b ^ (k[i] if i < len(k) else 0) for i, b in enumerate(data)])
