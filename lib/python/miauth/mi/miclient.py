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
from enum import Enum

from miauth.mi.micommand import MiCommand
from miauth.mi.micrypto import MiCrypto
from miauth.ble.base import BLEBase
from miauth.ble.uuid import UUID
from miauth.util import crc16


class MiClient(object):
    class State(Enum):
        INIT = -1
        RECV_INFO = 0
        SEND_KEY = 1
        RECV_KEY = 2
        SEND_DID = 3
        CONFIRM = 4
        COMM_SEND = 5
        COMM_RECV = 6

    def __init__(self, ble: BLEBase, debug=False):
        self.ble = ble
        self.debug = debug

        # TODO: implement power button press recognition self.button = False

        # state machine is supplied with a sequence of ...
        # if seq = [<state>, <on_state_enter_func()>]
        # TODO: create sequence controller class
        self.seq = ((MiClient.State.INIT, None),)
        self.seq_idx = -1

        # authentication related stuff
        self.remote_info = b''
        self.remote_key = b''
        self.token = b''
        self.keys = b''

        # counter for sent uart commands
        self.uart_it = 0

        self.clear_buffer()

    def clear_buffer(self):
        # buffer for send handler
        self.send_data = b''

        # buffer for receive handler
        self.expected_frames = 0
        self.expected_command = b''
        self.received_data = b''

        # counter for rogue message headers
        self.uart_ignore = 0

    def main_handler(self, data):
        if not data:
            if self.debug:
                print("<- Empty data")
            return

        if self.debug:
            print("<-", data.hex(" "))

        if data in MiCommand.AUTH_ERRORS:
            raise Exception("Authentication failed!"
                            "Previous session not reset, BLE DID missing or something.")
        elif self.get_state() == MiClient.State.COMM_RECV:
            if data[:2] == bytes.fromhex("55ab"):
                if self.expected_frames:
                    if data[2] != self.expected_frames:
                        print("(Rogue packet header received, start ignoring)")
                        self.uart_ignore += 1
                        return
                else:
                    # this is the case for non-read commands
                    self.expected_frames = data[2]

            if self.uart_ignore:
                if self.debug:
                    print("(Message ignored)")
                if self.uart_ignore > 3:
                    # correct command never came
                    self.set_state(MiClient.State.COMM_SEND)
                return

            self.received_data += data
            if len(self.received_data) >= self.expected_frames * 2:
                dst, cmd, dec = self.decrypt(self.received_data)
                if self.expected_frames == len(dec) + 2\
                   and dst >= 0x23\
                   and cmd == self.expected_command:
                    self.received_data = dec
                    self.set_state(MiClient.State.COMM_SEND)
                else:
                    raise Exception("Invalid response received.")
        elif data in MiCommand.ALL\
                or (data[0] > 0 and data[0] <= self.expected_frames):
            frm = data[0]
            if len(data) > 1:
                frm += 0x100 * data[1]

            if self.get_state() in [MiClient.State.RECV_INFO,
                                    MiClient.State.RECV_KEY]:
                self.receive_handler(frm, data)
            elif self.get_state() in [MiClient.State.SEND_KEY,
                                      MiClient.State.SEND_DID]:
                self.send_handler(frm, data)
            elif self.get_state() == MiClient.State.CONFIRM:
                self.confirm_handler(frm, data)

    def connect(self):
        self.ble.connect()

    def disconnect(self):
        self.ble.disconnect()

    def reset(self):
        self.ble.disconnect()
        self.__init__(self.ble, debug=self.debug)

    def get_state(self):
        return self.seq[self.seq_idx][0]

    def set_state(self, state):
        for i, s in enumerate(self.seq):
            if s[0] == state:
                self.seq_idx = i
                self.exec_state()
                return
        raise Exception(f"{state} not defined in sequence.")

    def exec_state(self):
        f = self.seq[self.seq_idx][1]
        if f is not None:
            f()

    def next_state(self):
        self.seq_idx += 1
        if self.seq_idx >= len(self.seq):
            if self.debug:
                print("Next state requested, but there's none. Resetting.")
            self.seq_idx = 0

        if self.debug:
            print("New state:", self.get_state())

        self.exec_state()

    def receive_handler(self, frm, data):
        if frm == 0:
            self.expected_frames = data[4] + 0x100 * data[5]
            if self.debug:
                print("Expecting", self.expected_frames, "frames")

            self.received_data = b''
            self.ble.write(UUID.AVDTP, MiCommand.RCV_RDY)
        else:
            self.received_data += data[2:]

        if frm == self.expected_frames:
            if self.debug:
                print("<<--", self.received_data.hex(" "))
            self.ble.write(UUID.AVDTP, MiCommand.RCV_OK)
            self.next_state()

    def send_handler(self, frm, data):
        if frm != 0:
            raise Exception("Mi unknown error. Try register.")

        if data == MiCommand.RCV_RDY:
            if self.debug:
                print("Mi ready to receive key")
            self.ble.write_parcel(UUID.AVDTP, self.send_data)
        elif data == MiCommand.RCV_TOUT:
            raise Exception("Mi sent RCV timeout.")
        elif data == MiCommand.RCV_ERR:
            raise Exception("Mi sent some RCV error?")
        elif data == MiCommand.RCV_OK:
            if self.debug:
                print("Mi confirmed key receive")
            self.next_state()

    def confirm_handler(self, frm, data):
        if data == MiCommand.CFM_REGISTER_OK:
            print("Mi authentication successful!")
        elif data == MiCommand.CFM_REGISTER_ERR:
            print("Mi authentication failed!")
        elif data == MiCommand.CFM_LOGIN_OK:
            print("Mi login successful!")
        elif data == MiCommand.CFM_LOGIN_ERR:
            print("Mi login failed!")
        else:
            print("Mi unknown response...")
        self.next_state()

    def calc_did(self, private_key):
        remote_pub_key = MiCrypto.bytes_to_pub_key(self.remote_key)
        e_share_key = MiCrypto.generate_secret(private_key, remote_pub_key)

        derived_key = MiCrypto.derive_key(e_share_key)

        token = derived_key[0:12]
        bind_key = derived_key[12:28]
        a = derived_key[28:44]

        did = self.remote_info
        did_ct = MiCrypto.encrypt_did(a, did)

        if self.debug:
            print("eShareKey:", e_share_key.hex())
            print("HKDF result: ", derived_key.hex())
            print("token:", token.hex())
            print("bind_key:", bind_key.hex())
            print("did:", did.decode())
            print("A:", a.hex())
            print("AES did CT: ", did_ct.hex())

        return did_ct, token

    def calc_login_info(self, random_key):
        salt = random_key + self.remote_key
        salt_inv = self.remote_key + random_key

        derived_key = MiCrypto.derive_key(self.token, salt=salt)
        keys = {
            'dev_key': derived_key[:16],
            'app_key': derived_key[16:32],
            'dev_iv': derived_key[32:36],
            'app_iv': derived_key[36:40],
        }
        info = MiCrypto.hash(keys['app_key'], salt)
        expected_remote_info = MiCrypto.hash(keys['dev_key'], salt_inv)

        if self.debug:
            print("HKDF result:", derived_key.hex())
            for key, val in keys.items():
                print(f"{key.upper()}:", val.hex())

        return info, expected_remote_info, keys

    def register(self, did=None):
        priv_key, pub_key = MiCrypto.gen_keypair()
        if self.debug:
            print("Private Key (Val):", MiCrypto.private_key_to_val(priv_key))
            print("Public Key (Hex):", MiCrypto.pub_key_to_bytes(pub_key).hex())

        def on_init_state():
            self.ble.set_handler(self.main_handler)
            self.next_state()

        def on_recv_info_state():
            self.ble.write(UUID.UPNP, MiCommand.CMD_GET_INFO)

        def on_send_key_state():
            self.remote_info = self.received_data[4:]
            if not self.remote_info:
                if did is None:
                    raise Exception("Remote info empty, "
                                    "connect device to official app first "
                                    "or supply 'register_did' parameter.")
                self.remote_info = did.encode() + b'\0'
            if len(self.remote_info) != 20:
                raise Exception("Remote info has wrong length.")

            if self.debug:
                print("Remote info received:", self.remote_info.hex())

            self.send_data = MiCrypto.pub_key_to_bytes(pub_key)
            self.ble.write(UUID.UPNP, MiCommand.CMD_SET_KEY)
            self.ble.write(UUID.AVDTP, MiCommand.CMD_SEND_DATA)

        def on_send_did_state():
            self.remote_key = self.received_data
            if self.debug:
                print("Remote key received:", self.remote_key.hex())

            self.send_data, self.token = self.calc_did(priv_key)
            self.ble.write(UUID.AVDTP, MiCommand.CMD_SEND_DID)

        def on_confirm_state():
            self.ble.write(UUID.UPNP, MiCommand.CMD_AUTH)

        self.seq = (
            (MiClient.State.INIT, on_init_state),
            (MiClient.State.RECV_INFO, on_recv_info_state),
            (MiClient.State.SEND_KEY, on_send_key_state),
            (MiClient.State.RECV_KEY, None),
            (MiClient.State.SEND_DID, on_send_did_state),
            (MiClient.State.CONFIRM, on_confirm_state),
            (MiClient.State.COMM_SEND, None),
        )
        self.seq_idx = -1

        self.next_state()
        while self.get_state() != MiClient.State.COMM_SEND:
            self.ble.wait_notify(secs=3.0)

            if self.get_state() != MiClient.State.COMM_SEND:
                # Trick 17: if no response ...
                # disconnect here and wait for power button press
                # after button press, reconnect and restart from beginning
                self.reset()

                print(">> Please press power button within 5 secs after beep")
                time.sleep(5)
                self.ble.connect()

                return self.register(did=did)  # return because of recursion
            else:
                break

    def save_token(self, filename):
        with open(filename, 'wb') as f:
            f.write(self.token)

    def load_token(self, filename):
        with open(filename, 'rb') as f:
            self.token = f.read()

    def login(self):
        rand_key = MiCrypto.gen_rand_key()

        def on_init_state():
            self.ble.set_handler(self.main_handler)
            self.next_state()

        def on_send_key_state():
            self.send_data = rand_key
            self.ble.write(UUID.UPNP, MiCommand.CMD_LOGIN)
            self.ble.write(UUID.AVDTP, MiCommand.CMD_SEND_KEY)

        def on_recv_info_state():
            self.remote_key = self.received_data
            if self.debug:
                print("Remote key received:", self.remote_key.hex())

        def on_send_did_state():
            self.remote_info = self.received_data
            if self.debug:
                print("Remote info received:", self.remote_info.hex())

            self.send_data, expected_remote_info, self.keys = self.calc_login_info(rand_key)
            if (self.remote_info != expected_remote_info):
                raise Exception("Remote info doesn't match expected info, try registering again.")
            self.ble.write(UUID.AVDTP, MiCommand.CMD_SEND_INFO)

        def on_comm_send_state():
            if self.debug:
                print("(Pause listening)")
            self.ble.pause_listening()

        def on_comm_recv_state():
            self.clear_buffer()
            if self.debug:
                print("(Resuming listening)")
            self.ble.resume_listening()

        self.seq = (
            (MiClient.State.INIT, on_init_state),
            (MiClient.State.SEND_KEY, on_send_key_state),
            (MiClient.State.RECV_KEY, None),
            (MiClient.State.RECV_INFO, on_recv_info_state),
            (MiClient.State.SEND_DID, on_send_did_state),
            (MiClient.State.CONFIRM, None),
            (MiClient.State.COMM_SEND, on_comm_send_state),
            (MiClient.State.COMM_RECV, on_comm_recv_state),
        )
        self.seq_idx = -1

        self.next_state()
        while self.get_state() != MiClient.State.COMM_SEND:
            self.ble.wait_notify(secs=3.0)

    def send_encrypted(self, cmd):
        res = MiCrypto.encrypt_uart(self.keys['app_key'],
                                    self.keys['app_iv'],
                                    cmd,
                                    it=self.uart_it)
        if self.debug:
            print("-->>", res.hex(" "))
        self.ble.write_chunked(UUID.TX, res)
        self.uart_it += 1
        self.expected_command = cmd[4:6]
        if self.expected_command[0] == 1:
            self.expected_frames = cmd[-1] + 2

    def decrypt(self, data):
        dec = MiCrypto.decrypt_uart(
            self.keys['dev_key'],
            self.keys['dev_iv'],
            data)[:-4]  # truncate checksum
        if self.debug:
            print("<<--", dec.hex(" "))
        # return dst, cmd, decoded data
        return dec[0], dec[1:3], dec[3:]

    def comm(self, cmd):
        if self.get_state() != MiClient.State.COMM_SEND:
            raise Exception("Not in COMM_SEND state. Retry maybe?")

        if type(cmd) not in [bytearray, bytes]:
            cmd = bytes.fromhex(cmd)
        if self.debug:
            print("->", cmd.hex(" "))

        if cmd[:2] != b'\x55\xaa':
            raise Exception("Command must start with 55 aa (M365 protocol)!")

        self.set_state(MiClient.State.COMM_RECV)
        if not self.keys:
            self.ble.write_chunked(UUID.TX, cmd)
            self.ble.wait_notify()

            if not self.received_data:
                raise Exception("No answer received. Try login first.")

            return self.received_data

        self.send_encrypted(cmd)

        self.ble.wait_notify()

        if not self.received_data:
            if self.debug:
                print("Timeout, no answer received")
            return b''

        return self.received_data
