#
#     MiAuth - Authenticate and interact with Xiaomi devices over BLE
#     Copyright (C) 2022  Daljeet Nandha
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
from miauth.ble.base import BLEBase
from miauth.ble.uuid import UUID

from bluepy import btle


class BluePy(BLEBase, btle.DefaultDelegate):
    def __init__(self, mac):
        self.p = btle.Peripheral()
        self.mac = mac

        self.handler = None

        self.channels = {
            UUID.AVDTP: None,
            UUID.UPNP: None,
            UUID.TX: None,
            UUID.RX: None,
            UUID.KEY: None,
        }

        btle.DefaultDelegate.__init__(self)
        BLEBase.__init__(self)

    def handleNotification(self, handle, data):
        if self.handler is None:
            raise Exception("BLE set handler first")
        if not data:
            return

        self.handler(data)

    def set_handler(self, handler):
        self.handler = handler

    def enable_notify(self, ch):
        val = b'\x01\x00'
        resp = self.p.writeCharacteristic(ch.valHandle + 1, val, True)
        if resp['rsp'][0] != 'wr':
            raise Exception("BLE could not setup notifications.")

    def disable_notify(self, ch):
        val = b'\x00\x00'
        resp = self.p.writeCharacteristic(ch.valHandle + 1, val, True)
        if resp['rsp'][0] != 'wr':
            raise Exception("BLE could not setup notifications.")

    def read(self, ch):
        return self.channels[ch].read()

    def write(self, ch, data, resp=False):
        self.channels[ch].write(data, resp)

    def write_chunked(self, ch, data, resp=False, chunk_size=20):
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            self.write(ch, chunk, resp=resp)

    def write_parcel(self, ch, data, resp=False, chunk_size=18):
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            chunk = bytes([i // chunk_size + 1, 0]) + chunk
            self.write(ch, chunk, resp=resp)

    def connect(self):
        self.p.connect(self.mac, btle.ADDR_TYPE_RANDOM)
        self.p.setDelegate(self)

        for ch in self.p.getCharacteristics():
            uuid = UUID.from_hex(ch.uuid.binVal.hex())
            self.channels[uuid] = ch
            if "NOTIFY" in ch.propertiesToString():
                print("enabling notifications for:", uuid)
                self.enable_notify(ch)

    def disconnect(self):
        self.disable_notify(self.channels[UUID.RX])
        self.p.disconnect()

    def wait_notify(self, secs=1.0):
        while self.p.waitForNotifications(secs):
            continue

    def read_device_name(self):
        ch = self.p.getCharacteristics(uuid=btle.AssignedNumbers.deviceName)
        if not ch:
            raise Exception("Device name not found.")

        return ch[0].read()

    def has_channel(self, name):
        return name in self.channels and self.channels[name] is not None
