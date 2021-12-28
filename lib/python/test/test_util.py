from unittest import TestCase

from miauth.util import crc16, int_to_bytes


class Test(TestCase):
    def test_int_to_bytes(self):
        b = int_to_bytes(1337)
        self.assertEqual(bytes([0x39, 5, 0, 0]), b, b.hex())

    def test_crc16(self):
        crc = crc16(bytes([0xa1, 0x21, 0xf3, 4, 5, 6, 7, 8, 9]))
        self.assertEqual(bytes.fromhex("23fe"), crc, crc.hex())
