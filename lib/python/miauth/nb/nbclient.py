#
#     MiAuth - Authenticate and interact with Xiaomi devices over BLE
#     Copyright (C) 2021-2022  Daljeet Nandha
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
import threading
from collections import deque
from enum import Enum
import secrets

from miauth.nb.nbcommand import NbCommand
from miauth.ble.uuid import UUID
from miauth.ble.base import BLEBase


class NbClient(object):
    class State(Enum):
        DISC = 0
        CON = 1
        PING = 2
        PRE = 3
        PAIR = 4
        COMM = 5

    APP_KEY = secrets.token_bytes(16)

    def __init__(self, ble: BLEBase, crypto, debug=False):
        self.ble = ble
        self.crypto = crypto
        self.debug = debug

        self.ble.set_handler(self.main_handler)

        self.received_serial = b''
        self.received_key = b''
        self.receive_buffer = b''
        self.send_buffer = deque()

        self.state = NbClient.State.DISC

    def main_handler(self, data):
        if data[:2] == b"\x5a\xa5":
            self.receive_buffer = data
        else:
            self.receive_buffer += data

        dec = self.crypto.decrypt(self.receive_buffer)
        if self.debug:
            print("Received message:", self.receive_buffer.hex(" "))
            print("Decoded message:", dec.hex(" "))

        if len(dec) == self.receive_buffer[2] + 7:
            cmd = dec[:NbCommand.ACK_LEN]
            payload = dec[NbCommand.ACK_LEN:]
            self.receive_handler(cmd, payload)

    def connect(self):
        self.ble.connect()
        self.state = NbClient.State.CON

    def disconnect(self):
        self.ble.disconnect()
        self.state = NbClient.State.DISC

    def receive_handler(self, cmd, payload):
        if self.debug:
            print("Got cmd:", cmd.hex(" "))

        if cmd == NbCommand.ACK_INIT:
            self.received_key = payload[:16]
            self.received_serial = payload[16:]
            if self.debug:
                print("> BLE Key:", self.received_key.hex(" "))
                print("> Serial:", self.received_serial.decode())
                print("Setting ble data/key in crypto")
            self.crypto.set_ble_data(self.received_key)

            self.state = NbClient.State.PING
        elif cmd == NbCommand.ACK_PRE:
            self.state = NbClient.State.PRE
        elif cmd == NbCommand.ACK_PING:
            if self.debug:
                print("Setting app data/key in crypto")

            self.crypto.set_app_data(NbClient.APP_KEY)

            self.state = NbClient.State.PAIR
        elif cmd == NbCommand.ACK_PAIR:
            print("Nb authentication successful!")

            self.state = NbClient.State.COMM
        else:
            self.receive_buffer = payload

    def process_thread(self):
        while self.state != NbClient.State.COMM:
            if self.debug:
                print("Current state:", self.state)

            if self.state == NbClient.State.CON:
                self.send_buffer.append(
                    self.crypto.encrypt(NbCommand.CMD_INIT)
                )
            elif self.state == NbClient.State.PING:
                self.send_buffer.append(
                    self.crypto.encrypt(NbCommand.CMD_PING(NbClient.APP_KEY))
                )
            elif self.state == NbClient.State.PRE:
                print(">> Please press the POWER button on the device")

                # Can send either Ping or Pair message, doesn't matter
                self.send_buffer.append(
                    self.crypto.encrypt(NbCommand.CMD_PAIR(self.received_serial))
                )
            elif self.state == NbClient.State.PAIR:
                self.send_buffer.append(
                    self.crypto.encrypt(NbCommand.CMD_PAIR(self.received_serial))
                )

            time.sleep(2.0)

    def send_thread(self):
        while self.state != NbClient.State.DISC:
            if not self.send_buffer:
                time.sleep(1.0)
                continue

            msg = self.send_buffer.pop()
            if self.debug:
                print("Sending message:", msg.hex(" "))

            # frame has 32 - 12 = 20 bytes --> need to chunk!!
            msg_len = len(msg)
            byte_idx = 0
            while msg_len > 0:
                tmp_len = msg_len if msg_len <= 20 else 20
                buf = msg[byte_idx:byte_idx + tmp_len]
                self.ble.write(UUID.TX, buf)

                msg_len -= tmp_len
                byte_idx += tmp_len

            time.sleep(1.0)

    def auth(self):
        self.crypto.set_name(self.ble.read_device_name())

        threading.Thread(target=self.process_thread).start()
        threading.Thread(target=self.send_thread).start()

        while self.state != NbClient.State.COMM:
            time.sleep(1.0)

    def comm(self, cmd):
        if self.state != NbClient.State.COMM:
            raise Exception("Not in COMM state. Retry.")

        if type(cmd) not in [bytearray, bytes]:
            cmd = bytes.fromhex(cmd)

        self.receive_buffer = b''
        while not self.receive_buffer:
            self.send_buffer.append(self.crypto.encrypt(cmd))
            time.sleep(2.0)

        return self.receive_buffer
