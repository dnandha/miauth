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
from miauth.mi.micrypto import MiCrypto
from miauth.uuid import UUID


class MiClient(btle.DefaultDelegate):
    class State(object):
        INIT = -1
        RECV_INFO = 0
        SEND_KEY = 1
        RECV_KEY = 2
        SEND_DID = 3
        CONFIRM = 4
        COMM = 5

    def __init__(self, p, mac, debug=False):
        self.p = p
        self.mac = mac
        self.debug = debug

        btle.DefaultDelegate.__init__(self)

        self.ch_avdtp, self.ch_upnp = None, None
        self.ch_tx, self.ch_rx = None, None

        # TODO: implement power button press recognition self.button = False
        # self.s = btle.Scanner().withDelegate(self)

        # state machine is supplied with a sequence of ...
        # if seq = [<state>, <on_state_enter_func()>]
        # TODO: create sequence controller class
        self.seq = ()
        self.seq_idx = 0

        # buffer for send handler
        self.send_data = b''

        # buffer for receive handler
        self.receive_frames = 0
        self.received_data = b''

        # authentication related stuff
        self.remote_info = b''
        self.remote_key = b''
        self.token = b''
        self.keys = b''

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

    def bt_write_parcel(self, char, data, resp=False, chunk_size=18):
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            chunk = bytes([i // chunk_size + 1, 0]) + chunk
            self.bt_write(char, chunk, resp=resp)

    def connect(self):
        self.p.connect(self.mac, btle.ADDR_TYPE_RANDOM)
        self.p.setDelegate(self)

        svc = self.p.getServiceByUUID(UUID.AUTH)
        self.ch_avdtp = svc.getCharacteristics(UUID.AVDTP)[0]
        self.ch_upnp = svc.getCharacteristics(UUID.UPNP)[0]

        svc = self.p.getServiceByUUID(UUID.UART)
        self.ch_tx = svc.getCharacteristics(UUID.TX)[0]
        self.ch_rx = svc.getCharacteristics(UUID.RX)[0]

        self.enable_notify(self.ch_avdtp)
        self.enable_notify(self.ch_upnp)
        self.enable_notify(self.ch_rx)

    def disconnect(self):
        self.p.disconnect()

    def reset(self):
        self.enable_notify(self.ch_rx, reset=True)
        self.p.disconnect()
        self.__init__(self.p, self.mac, debug=self.debug)

    def get_state(self):
        return self.seq[self.seq_idx][0]

    def next_state(self):
        self.seq_idx += 1

        # exec entry func
        f = self.seq[self.seq_idx][1]
        if f is not None:
            f()

    def main_handler(self, data):
        frm = data[0] + 0x100 * data[1]
        if self.debug:
            print("<-", data.hex(), frm)

        if self.get_state() in [MiClient.State.RECV_INFO,
                                MiClient.State.RECV_KEY]:
            self.receive_handler(frm, data)
        elif self.get_state() in [MiClient.State.SEND_KEY,
                                  MiClient.State.SEND_DID]:
            self.send_handler(frm, data)
        elif self.get_state() == MiClient.State.CONFIRM:
            self.confirm_handler(frm)
        elif self.get_state() == MiClient.State.COMM:
            # TODO: check if correct number of frames received
            self.received_data += data

    def receive_handler(self, frm, data):
        if frm == 0:
            self.receive_frames = data[4] + 0x100 * data[5]
            if self.debug:
                print("Expecting", self.receive_frames, "frames")

            self.received_data = b''
            self.bt_write(self.ch_avdtp, MiCommand.RCV_RDY)
        else:
            self.received_data += data[2:]

        if frm == self.receive_frames:
            if self.debug:
                print("All frames received: ", self.received_data.hex())
            self.bt_write(self.ch_avdtp, MiCommand.RCV_OK)
            self.next_state()

    def send_handler(self, frm, data):
        if frm != 0:
            return

        if data == MiCommand.RCV_RDY:
            if self.debug:
                print("Mi ready to receive key")
            self.bt_write_parcel(self.ch_avdtp, self.send_data)
        if data == MiCommand.RCV_TOUT:
            raise Exception("Mi sent RCV timeout.")
        if data == MiCommand.RCV_ERR:
            raise Exception("Mi sent some RCV error?")
        if data == MiCommand.RCV_OK:
            if self.debug:
                print("Mi confirmed key receive")
            self.next_state()

    def confirm_handler(self, frm):
        if frm == 0x11:
            print("Mi authentication successful!")
        elif frm == 0x12:
            print("Mi authentication failed!")
        elif frm == 0x21:
            print("Mi login successful!")
        elif frm == 0x23:
            print("Mi login failed!")
        else:
            print("Mi unknown response...")
        self.next_state()

    def calc_did(self, private_key):
        remote_pub_key = MiCrypto.decode_pub_key(self.remote_key)
        e_share_key = MiCrypto.create_e_share_key(remote_pub_key, private_key)

        derived_key = MiCrypto.derive_key(e_share_key)

        token = derived_key[0:12]
        bind_key = derived_key[12:28]
        a = derived_key[28:44]

        did_ct = MiCrypto.encrypt_did(a, self.remote_info[4:])

        if self.debug:
            print("eShareKey:", e_share_key.hex())
            print("HKDF result: ", derived_key.hex())
            print("token:", token.hex())
            print("bind_key:", bind_key.hex())
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

    def register(self):
        priv_key, pub_key = MiCrypto.gen_keypair()

        def on_recv_info_state():
            self.bt_write(self.ch_upnp, MiCommand.CMD_GET_INFO)

        def on_send_key_state():
            self.remote_info = self.received_data

            self.send_data = pub_key
            self.bt_write(self.ch_upnp, MiCommand.CMD_SET_KEY)
            self.bt_write(self.ch_avdtp, MiCommand.CMD_SEND_DATA)

        def on_send_did_state():
            self.remote_key = self.received_data

            self.send_data, self.token = self.calc_did(priv_key)
            self.bt_write(self.ch_avdtp, MiCommand.CMD_SEND_DID)

        def on_confirm_state():
            self.bt_write(self.ch_upnp, MiCommand.CMD_AUTH)

        self.seq = ((MiClient.State.INIT, None),
                    (MiClient.State.RECV_INFO, on_recv_info_state()),
                    (MiClient.State.SEND_KEY, on_send_key_state),
                    (MiClient.State.RECV_KEY, None),
                    (MiClient.State.SEND_DID, on_send_did_state),
                    (MiClient.State.CONFIRM, on_confirm_state),
                    (MiClient.State.COMM, None),
                    )
        self.seq_idx = 0

        self.next_state()
        while self.get_state() != MiClient.State.COMM:
            if self.p.waitForNotifications(3.0):
                continue

            # Trick 17: if no response ...
            # disconnect here and wait for power button press
            # after button press, reconnect and restart from beginning
            self.reset()

            print(">> Please press power button within 5 secs after beep")
            time.sleep(5)
            self.connect()

            return self.register()  # return because of recursion

    def save_token(self, filename):
        with open(filename, 'wb') as f:
            f.write(self.token)

    def load_token(self, filename):
        with open(filename, 'rb') as f:
            self.token = f.read()

    def login(self):
        rand_key = MiCrypto.gen_rand_key()

        def on_send_key_state():
            self.send_data = rand_key
            self.bt_write(self.ch_upnp, MiCommand.CMD_LOGIN)
            self.bt_write(self.ch_avdtp, MiCommand.CMD_SEND_KEY)

        def on_recv_info_state():
            self.remote_key = self.received_data

        def on_send_did_state():
            self.remote_info = self.received_data

            self.send_data, expected_remote_info, self.keys = self.calc_login_info(rand_key)
            assert self.remote_info == expected_remote_info, \
                f"{self.remote_info.hex()} != {expected_remote_info.hex()}"
            self.bt_write(self.ch_avdtp, MiCommand.CMD_SEND_INFO)

        self.seq = (
            (MiClient.State.INIT, None),
            (MiClient.State.SEND_KEY, on_send_key_state),
            (MiClient.State.RECV_KEY, None),
            (MiClient.State.RECV_INFO, on_recv_info_state),
            (MiClient.State.SEND_DID, on_send_did_state),
            (MiClient.State.CONFIRM, None),
            (MiClient.State.COMM, None),
        )
        self.seq_idx = 0

        self.next_state()
        while self.get_state() != MiClient.State.COMM:
            if self.p.waitForNotifications(3.0):
                continue

    def comm(self, cmd):
        if self.get_state() != MiClient.State.COMM:
            raise Exception("Not in COMM state. Retry maybe.")

        if type(cmd) not in [bytearray, bytes]:
            cmd = bytes.fromhex(cmd)

        if cmd[:2] != b'\x55\xAA':
            if cmd[:2] == b'\x5a\xa5':
                raise Exception("Command must start with 55 AA (M365 PROTOCOl)!\
                                You sent a Nb command, try Nb pairing instead.")
            else:
                raise Exception("Command must start with 55 AA (M365 PROTOCOl)!")

        self.received_data = b''
        if not self.keys:
            self.bt_write(self.ch_tx, cmd)

            while self.p.waitForNotifications(3.0):
                continue

            if not self.received_data:
                raise Exception("No answer received. Try login first.")

            return self.received_data

        res = MiCrypto.encrypt_uart(self.keys['app_key'], self.keys['app_iv'], cmd, it=self.uart_it)
        self.bt_write(self.ch_tx, res)
        self.uart_it += 1

        while self.p.waitForNotifications(3.0):
            continue

        if not self.received_data:
            raise Exception("No answer received. Firmware not supported.")

        return MiCrypto.decrypt_uart(self.keys['dev_key'], self.keys['dev_iv'], self.received_data)[3:-4]
