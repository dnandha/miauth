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

from miauth.mi.micrypto import MiCrypto


class TestMiCrypto(TestCase):
    def test_gen_rand_key(self):
        rand = MiCrypto.gen_rand_key()
        self.assertEqual(16, len(rand))

    def test_gen_keypair(self):
        _, pub_key = MiCrypto.gen_keypair()
        pub_key = MiCrypto.pub_key_to_bytes(pub_key)
        self.assertEqual(64, len(pub_key))

    def test_gen_private_key(self):
        val = 38598657185418289442228743809972412250162588503372669841026540598582897367118
        priv_key = MiCrypto.val_to_private_key(val)
        priv_val = MiCrypto.private_key_to_val(priv_key)
        pub = MiCrypto.pub_key_to_bytes(priv_key.public_key())
        self.assertEqual(val, priv_val)
        self.assertEqual(bytes.fromhex("b5dca0aec31a8932d0f53cbcbcf0cfdd833c355cada1025cc076e013439ddec2b4017b546a11d79a758db9d015a2ed8926cf82179b593679187d623b5e430fca"),
                         pub,
                         pub.hex(" "))

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
                         derived.hex(" "))

        derived = MiCrypto.derive_key(secret)
        self.assertEqual(bytes.fromhex("104ec0eda032b6d213c245359e585d3bfd4b7c5d683c99f49fd86aaf0de0f6b0bfafb897e3b3727aaa8f8ad6b21a737c1d85c3aae340969f268d2d95ca8848c1"),
                         derived,
                         derived.hex(" "))

    def test_hash(self):
        key = bytes.fromhex("E2B274F08128A62A9575288BED169B3E")
        hash = MiCrypto.hash(key, bytes([1, 2, 3, 4]))
        self.assertEqual(bytes.fromhex("235d7f910974acb594d76a1652a856ce4f269e3060d7c8512e94b2da345d3083"),
                         hash,
                         hash.hex(" "))

    def test_encrypt_did(self):
        key = bytes.fromhex("4FEB7165982BF1C6183A51B8CADD0EEC")
        ct = MiCrypto.encrypt_did(key, bytes([1, 2, 3, 4]))
        self.assertEqual(bytes.fromhex("aeebd70f8c2bdf8c"), ct, ct.hex())

    def test_encrypt_uart(self):
        app_key = bytes.fromhex("9951fb8edf3921d61d15d56b45d38a46")
        app_iv = bytes.fromhex("642b0a93")
        ct = MiCrypto.encrypt_uart(app_key, app_iv, bytes.fromhex("55aa032001100e"), rand=bytes([1, 2, 3, 4]))
        self.assertEqual(bytes.fromhex("55ab03000003dbfd07465635dcbd3b2d7acefa"), ct, ct.hex())

    def test_decrypt_uart(self):
        dev_key = bytes.fromhex("887ed6ae8ea3189546a55f0d0a6216ce")
        dev_iv = bytes.fromhex("659b7362")
        ct = MiCrypto.decrypt_uart(dev_key, dev_iv, bytes.fromhex("55ab1001004c4e49c65c208435f7e050e56904adb8fe6e2eb1297cf9e0afbaf2"))
        self.assertEqual(bytes.fromhex("23011032353730302f3030303031333337cd65c322"), ct, ct.hex())

    def test_register(self):
        priv_key = MiCrypto.val_to_private_key(48461508383982493215332654270464913273532832436436077476553357014100094140803)
        #print(MiCrypto.pub_key_to_bytes(priv_key.public_key()).hex(" "))
        
        remote_info = bytes.fromhex("0100000000626c742e342e31386e35383236366b67673030")
        remote_pub_key = MiCrypto.bytes_to_pub_key(bytes.fromhex("2afe2a8c1c56e5e70721665cd20d017273111ecaeceb1e4d641e7b7a122a9c3041e5cbc962eefbdb155ffd95847a0d8762803291fc2866c5672ceee0e77d77fc"))
        
        secret = MiCrypto.generate_secret(priv_key, remote_pub_key)
        derived = MiCrypto.derive_key(secret)
        did_key = derived[28:44]
        did_ct = MiCrypto.encrypt_did(did_key, remote_info[4:])
        self.assertEqual("fac3a6fd591dcea21f9f4fefe297804f49291527ae818b285f4a75a6fab72af8", secret.hex())
        self.assertEqual("0cf5615003810d89c233a12a8fc5100e31299d80c4c290dc7d33f19ec42ea48a95c5544f105fe7ebb8b39233c6542b1fff90b2206265080bf516365fd8d758fe", derived.hex())
        self.assertEqual("c42ea48a95c5544f105fe7ebb8b39233", did_key.hex())
        self.assertEqual("646735cc7a96373aabbd93afa089bb6cd2d080302101007a", did_ct.hex())

    def test_login(self):
        token = bytes.fromhex("0cf5615003810d89c233a12a")
        random_key = bytes.fromhex("a8699783c1f03c7b73a046cdb613a9bf")
        remote_key = bytes.fromhex("90fdec0ece05016d7f116b50fca4b4bf")
        
        remote_info = bytes.fromhex("471467ea7ed6064f8dd72f416c079dcb3bb78e3c94a51e97b98ef7623a7798e5")

        salt = random_key + remote_key
        salt_inv = remote_key + random_key

        derived_key = MiCrypto.derive_key(token, salt=salt)
        keys = {
            'dev_key': derived_key[:16],
            'app_key': derived_key[16:32],
            'dev_iv': derived_key[32:36],
            'app_iv': derived_key[36:40],
        }
        info = MiCrypto.hash(keys['app_key'], salt)
        expected_remote_info = MiCrypto.hash(keys['dev_key'], salt_inv)

        self.assertEqual(remote_info, expected_remote_info)
        self.assertEqual("bbb99b6a6f1ae419e3b13db93514f3e12a1843033f276392eea99068affca753", info.hex())
        self.assertEqual("3c2fdae69f8746663a7d91029724b072", keys['dev_key'].hex())
        self.assertEqual("12a4122dbe3cf60f3bdcb37139c34611", keys['app_key'].hex())
        self.assertEqual("cd016050", keys['dev_iv'].hex())
        self.assertEqual("c87de6f1", keys['app_iv'].hex())
