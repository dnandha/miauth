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
import time

from bluepy import btle

from miauth.mi.micommand import MiCommand
from miauth.uuid import UUID
from miauth.util import crc16


class M365Client(btle.DefaultDelegate):
    def __init__(self, p, mac, debug=False):
        self.p = p
        self.mac = mac
        self.debug = debug

        btle.DefaultDelegate.__init__(self)

        self.ch_tx = None
        self.ch_rx = None

        self.ch_key = None
        self.key = None

        # buffer for receive handler
        self.receive_frames = 0
        self.received_data = b''

        # counter for sent uart commands
        self.uart_it = 0

    def handleNotification(self, handle, data):
        self.main_handler(data)

    def enable_notify(self, ch, reset=False):
        val = b'\x01\x00' if not reset else b'\x00\x00'
        resp = self.p.writeCharacteristic(ch.valHandle + 1, val, True)
        if resp['rsp'][0] != 'wr':
            raise Exception("BLE could not setup notifications.")

    def bt_write(self, char, data, resp=False):
        if self.debug:
            print("->", data.hex())

        char.write(data, resp)

    def bt_write_chunked(self, char, data, resp=False, chunk_size=20):
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            self.bt_write(char, chunk, resp=resp)

    def connect(self):
        self.p.connect(self.mac, btle.ADDR_TYPE_RANDOM)
        self.p.setDelegate(self)

        svc = self.p.getServiceByUUID(UUID.UART)
        self.ch_tx = svc.getCharacteristics(UUID.TX)[0]
        self.ch_rx = svc.getCharacteristics(UUID.RX)[0]

        self.enable_notify(self.ch_rx)

        svc = self.p.getServiceByUUID(UUID.AUTH)
        self.ch_key = svc.getCharacteristics(UUID.KEY)
        if self.ch_key:
            # credits and thanks to https://github.com/Informatic/py9b
            print("found old 55ab encryption -> recovering key")
            self.key = self.ch_key[0].read()
            self.key += self._recover_key()
            if self.debug:
                print("key:", self.key.hex())

    def _recover_key(self):
        # credits and thanks to https://github.com/Informatic/py9b
        return self.comm("55aa0322015020")[9:]

    def disconnect(self):
        self.p.disconnect()

    def reset(self):
        self.enable_notify(self.ch_rx, reset=True)
        self.p.disconnect()
        self.__init__(self.p, self.mac, debug=self.debug)

    def main_handler(self, data):
        if len(data) == 0:
            return
        self.received_data += data

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
        self.bt_write_chunked(self.ch_tx, res)
        self.uart_it += 1

        while self.p.waitForNotifications(2.0):
            continue

        if not self.received_data:
            raise Exception("No answer received. Firmware not supported.")

        if self.debug:
            print("received:", self.received_data.hex())
        res = self.received_data
        if crc16(res[2:-2]) != res[-2:]:
            raise Exception("Checksum mismatch in response")

        if self.key:
            res = self.crypt(res[3:])[:-4]

        if self.debug:
            print("response:", res.hex())
        return res[3:-2]

    def crypt(self, data):
        # credits and thanks to https://github.com/Informatic/py9b
        k = self.key
        return bytearray([b ^ (k[i] if i < len(k) else 0) for i, b in enumerate(data)])
