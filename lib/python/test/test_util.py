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
from unittest import TestCase

from miauth.util import crc16, int_to_bytes


class Test(TestCase):
    def test_int_to_bytes(self):
        b = int_to_bytes(1337)
        self.assertEqual(bytes([0x39, 5, 0, 0]), b, b.hex(" "))

    def test_crc16(self):
        crc = crc16(bytes([0xa1, 0x21, 0xf3, 4, 5, 6, 7, 8, 9]))
        self.assertEqual(bytes.fromhex("23fe"), crc, crc.hex(" "))
