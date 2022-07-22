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
class MiCommand(object):
    CMD_GET_INFO = b"\xa2\x00\x00\x00"
    CMD_SET_KEY = b"\x15\x00\x00\x00"
    CMD_LOGIN = b"\x24\x00\x00\x00"
    CMD_AUTH = b"\x13\x00\x00\x00"

    CMD_SEND_DATA = b"\x00\x00\x00\x03\x04\x00"
    CMD_SEND_DID = b"\x00\x00\x00\x00\x02\x00"
    CMD_SEND_KEY = b"\x00\x00\x00\x0b\x01\x00"
    CMD_SEND_INFO = b"\x00\x00\x00\x0a\x02\x00"

    RCV_RDY = b"\x00\x00\x01\x01"
    RCV_OK = b"\x00\x00\x01\x00"
    RCV_TOUT = b"\x00\x00\x01\x05\x01\x00"
    RCV_ERR = b"\x00\x00\x01\x05\x03\x00"

    RCV_RESP_KEY = b"\x00\x00\x00\x0d\x01\x00"
    RCV_RESP_INFO = b"\x00\x00\x00\x0c\x02\x00"

    CFM_REGISTER_OK = b'\x11\x00\x00\x00'
    CFM_REGISTER_ERR = b'\x12\x00\x00\x00'
    CFM_LOGIN_OK = b'\x21\x00\x00\x00'
    CFM_LOGIN_ERR = b'\x23\x00\x00\x00'

    AUTH_ERR0 = b'\xe0\x00\x00\x00'
    AUTH_ERR1 = b'\xe1\x00\x00\x00'
    AUTH_ERR2 = b'\xe2\x00\x00\x00'
    AUTH_ERR3 = b'\xe3\x00\x00\x00'

    ALL = [
        CMD_GET_INFO, CMD_SET_KEY, CMD_LOGIN, CMD_AUTH,
        CMD_SEND_DATA, CMD_SEND_DID, CMD_SEND_KEY, CMD_SEND_INFO,
        RCV_RDY, RCV_OK, RCV_TOUT, RCV_ERR,
        RCV_RESP_KEY, RCV_RESP_INFO,
        CFM_REGISTER_OK, CFM_REGISTER_ERR, CFM_LOGIN_OK, CFM_LOGIN_ERR
    ]

    AUTH_ERRORS = [
        AUTH_ERR0, AUTH_ERR1, AUTH_ERR2, AUTH_ERR3
    ]
