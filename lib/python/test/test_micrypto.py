from unittest import TestCase

from miauth.mi.micrypto import MiCrypto


class TestMiCrypto(TestCase):
    def test_gen_rand_key(self):
        rand = MiCrypto.gen_rand_key()
        self.assertEqual(16, len(rand))

    def test_gen_keypair(self):
        _, pub_key = MiCrypto.gen_keypair()
        pub_key = MiCrypto.pub_key_to_bytes(pub_key)
        self.assertEqual(64, len(pub_key))

    def test_create_e_share_key(self):
        kp1 = MiCrypto.gen_keypair()
        kp2 = MiCrypto.gen_keypair()
        secret1 = MiCrypto.generate_secret(kp1[0], kp2[1])
        secret2 = MiCrypto.generate_secret(kp2[0], kp1[1])
        self.assertEqual(secret1, secret2)
        self.assertEqual(32, len(secret1))

    def test_derive_key(self):
        secret = bytes.fromhex("5a3d987d45f6484aff82ffde1e9105b7f6cc79fa7467f12c5855ad9e3f1d8f2f")
        derived = MiCrypto.derive_key(secret, bytes([1, 2, 3, 4]))
        self.assertEqual(bytes.fromhex("40ccc0ee058c3a1d37c08e6f72bc2c57c0a406aaa801a0b1b72f22c8c3ec930d3f151e2eb38a2303d8625a18084daa15667496dcfbc53ba3074ce35d6c90d987"),
                         derived,
                         derived.hex())

        derived = MiCrypto.derive_key(secret)
        self.assertEqual(bytes.fromhex("104ec0eda032b6d213c245359e585d3bfd4b7c5d683c99f49fd86aaf0de0f6b0bfafb897e3b3727aaa8f8ad6b21a737c1d85c3aae340969f268d2d95ca8848c1"),
                         derived,
                         derived.hex())

    def test_hash(self):
        key = bytes.fromhex("E2B274F08128A62A9575288BED169B3E")
        hash = MiCrypto.hash(key, bytes([1, 2, 3, 4]))
        self.assertEqual(bytes.fromhex("235d7f910974acb594d76a1652a856ce4f269e3060d7c8512e94b2da345d3083"),
                         hash,
                         hash.hex())

    def test_encrypt_did(self):
        key = bytes.fromhex("4FEB7165982BF1C6183A51B8CADD0EEC")
        ct = MiCrypto.encrypt_did(key, bytes([1, 2, 3, 4]))
        self.assertEqual(bytes.fromhex("aeebd70f8c2bdf8c"), ct, ct.hex())

    def test_encrypt_uart(self):
        key = bytes.fromhex("239b3c7e92dc6d6d2fa174a215aedf2e")
        iv = bytes([1, 2])
        ct = MiCrypto.encrypt_uart(key, iv, bytes.fromhex("55aa032001100e"), rand=bytes([1, 2, 3, 4]))
        self.assertEqual(bytes.fromhex("55ab030000adf399086b9e0bd059366ad10dfa"), ct, ct.hex())

    def test_decrypt_uart(self):
        key = bytes.fromhex("239b3c7e92dc6d6d2fa174a215aedf2e")
        iv = bytes([1, 2])
        msg = MiCrypto.decrypt_uart(key, iv, bytes.fromhex("55ab030000adf399084637f7234162d70d9dfa"))
        self.assertEqual(bytes.fromhex("2001100e2cabfff7"), msg, msg.hex())
