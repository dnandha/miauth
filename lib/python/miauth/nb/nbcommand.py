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
class NbCommand(object):
    CMD_INIT = bytes.fromhex("5AA5003D215B00")
    CMD_PING = lambda rand: bytes.fromhex("5AA5103D215C00" + rand.hex())
    CMD_PAIR = lambda serial: bytes.fromhex("5AA50E3D215D00" + serial.hex())

    ACK_INIT = bytes.fromhex("5AA51E213D5B01")
    ACK_PRE = bytes.fromhex("5AA500213D5C00")
    ACK_PING = bytes.fromhex("5AA500213D5C01")
    ACK_PAIR = bytes.fromhex("5AA500213D5D01")
    ACK_LEN = len(ACK_INIT)
