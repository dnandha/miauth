// Copyright 2022 Daljeet Nandha
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package de.nandtek.miauth;

import junit.framework.TestCase;

import org.junit.Assert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;


public class CryptoTest extends TestCase {

    public void testRandomKey() {
        byte[] rand = Crypto.generateRandomKey();
        Assert.assertEquals(rand.length, 16);
    }
    public void testGenerateKeyPair() {
        KeyPair kp = Crypto.generateKeyPair();
        Assert.assertEquals(64, Crypto.publicKeyToBytes(kp.getPublic()).length);
    }

    public void testGeneratePrivateKey() {
        byte[] privBytes = Util.hexToBytes("555610d6677f6309a23af6188ca933a36e8cc7cf28791afa3cd809adfc75584e");
        byte[] pubBytes = Util.hexToBytes("b5dca0aec31a8932d0f53cbcbcf0cfdd833c355cada1025cc076e013439ddec2b4017b546a11d79a758db9d015a2ed8926cf82179b593679187d623b5e430fca");
        PrivateKey priv = Crypto.generatePrivateKey(privBytes);
        PublicKey pub = Crypto.generatePublicKey(pubBytes);
        Assert.assertArrayEquals(privBytes, Crypto.privateKeyToBytes(priv));
        Assert.assertArrayEquals(pubBytes, Crypto.publicKeyToBytes(pub));
    }

    public void testGeneratePublicKey() {
        byte[] pkBytesIn = Util.hexToBytes("b7f56851cd47ff5ba25ce521e124218e6ec43fc1a0782d974559ce9989a1e8372e663a5e91b5d305769b1decc6522d237f667c6a20cf0f7186e299a23d6f595b");
        PublicKey pk = Crypto.generatePublicKey(pkBytesIn);
        byte[] pkBytesOut = Crypto.publicKeyToBytes(pk);
        Assert.assertEquals(Util.bytesToHex(pkBytesIn), Util.bytesToHex(pkBytesOut));
    }

    public void testGenerateSecretDH() {
        KeyPair kp1 = Crypto.generateKeyPair();
        KeyPair kp2 = Crypto.generateKeyPair();
        byte[] secret1 = Crypto.generateSecret(kp1.getPrivate(), kp2.getPublic());
        byte[] secret2 = Crypto.generateSecret(kp2.getPrivate(), kp1.getPublic());
        Assert.assertEquals(Util.bytesToHex(secret1), Util.bytesToHex(secret2));
        Assert.assertEquals(secret1.length, 32);
    }

    public void testGenerateSecret() {
        byte[] privBytes = Util.hexToBytes("555610d6677f6309a23af6188ca933a36e8cc7cf28791afa3cd809adfc75584e");
        byte[] pubBytes = Util.hexToBytes("b5dca0aec31a8932d0f53cbcbcf0cfdd833c355cada1025cc076e013439ddec2b4017b546a11d79a758db9d015a2ed8926cf82179b593679187d623b5e430fca");
        PrivateKey priv = Crypto.generatePrivateKey(privBytes);
        PublicKey pub = Crypto.generatePublicKey(pubBytes);
        byte[] secret = Crypto.generateSecret(priv, pub);
        Assert.assertEquals("70b646a735a72e56845aaf83777463fac250b6da0e864526b312a7e56b5c0f36", Util.bytesToHex(secret));
    }

    public void testHash() {
        byte[] key = Util.hexToBytes("E2B274F08128A62A9575288BED169B3E");
        byte[] hash = Crypto.hash(key, new byte[]{1, 2, 3, 4});
        Assert.assertEquals("235d7f910974acb594d76a1652a856ce4f269e3060d7c8512e94b2da345d3083", Util.bytesToHex(hash));
    }

    public void testDeriveSecret() {
        byte[] secret = Util.hexToBytes("5a3d987d45f6484aff82ffde1e9105b7f6cc79fa7467f12c5855ad9e3f1d8f2f");
        byte[] derived = Crypto.deriveSecret(secret, new byte[]{1, 2, 3, 4});
        Assert.assertEquals(
                "40ccc0ee058c3a1d37c08e6f72bc2c57c0a406aaa801a0b1b72f22c8c3ec930d3f151e2eb38a2303d8625a18084daa15667496dcfbc53ba3074ce35d6c90d987",
                Util.bytesToHex(derived)
        );

        derived = Crypto.deriveSecret(secret, null);
        Assert.assertEquals(
                "104ec0eda032b6d213c245359e585d3bfd4b7c5d683c99f49fd86aaf0de0f6b0bfafb897e3b3727aaa8f8ad6b21a737c1d85c3aae340969f268d2d95ca8848c1",
                Util.bytesToHex(derived)
        );
    }

    public void testEncryptDid() {
        byte[] key = Util.hexToBytes("4FEB7165982BF1C6183A51B8CADD0EEC");
        byte[] ct = Crypto.encryptDid(key, new byte[]{1, 2, 3, 4});
        Assert.assertEquals("aeebd70f8c2bdf8c", Util.bytesToHex(ct));
    }

    public void testEncryptUart() {
        byte[] key = Util.hexToBytes("239b3c7e92dc6d6d2fa174a215aedf2e");
        String inp = "55aa032001100e";
        byte[] msg = Crypto.encryptUart(key, new byte[]{1, 2}, Util.hexToBytes(inp), 0, new byte[] {1,2,3,4});
        Assert.assertEquals("55ab030000adf399086b9e0bd059366ad10dfa", Util.bytesToHex(msg));
    }

    public void testDecryptUart() {
        byte[] key = Util.hexToBytes("239b3c7e92dc6d6d2fa174a215aedf2e");
        byte[] msg = Util.hexToBytes("55ab030000adf399084637f7234162d70d9dfa");
        byte[] dec = Crypto.decryptUart(key, new byte[]{1, 2}, msg);
        Assert.assertEquals("2001100e2cabfff7", Util.bytesToHex(dec));
    }

    public void testEncryptUartWeak() {
        byte[] key = Util.hexToBytes("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75");
        String inp = "55aa032001100e";
        byte[] msg = Crypto.encryptUartWeak(key, Util.hexToBytes(inp), new byte[] {0,0,0,0});
        Assert.assertEquals("55ab03fe19994fa3375d3a8cfc", Util.bytesToHex(msg));
    }

    public void testDecryptUartWeak() {
        byte[] key = Util.hexToBytes("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75");
        byte[] msg = Util.hexToBytes("55ab10fd19997396006d0aa5362e57675fa15ef08906519d2ef7");
        byte[] dec = Crypto.decryptUartWeak(key, msg);
        Assert.assertEquals("23011032353730302f3030303031333337", Util.bytesToHex(dec));
    }

    public void testRegister() {
        BigInteger val = new BigInteger("48461508383982493215332654270464913273532832436436077476553357014100094140803");
        PrivateKey privKey = Crypto.generatePrivateKey(val);

        byte[] remoteInfo = Util.hexToBytes("0100000000626c742e342e31386e35383236366b67673030");
        byte[] remotePubKeyD = Util.hexToBytes("2afe2a8c1c56e5e70721665cd20d017273111ecaeceb1e4d641e7b7a122a9c3041e5cbc962eefbdb155ffd95847a0d8762803291fc2866c5672ceee0e77d77fc");
        PublicKey remotePubKey = Crypto.generatePublicKey(remotePubKeyD);

        byte[] secret = Crypto.generateSecret(privKey, remotePubKey);
        byte[] derived = Crypto.deriveSecret(secret, null);
        byte[] token = Arrays.copyOfRange(derived, 0, 12);
        byte[] bindKey = Arrays.copyOfRange(derived, 12, 28);
        byte[] didKey = Arrays.copyOfRange(derived, 28, 44);
        byte[] junk = Arrays.copyOfRange(derived, 44, 64);

        byte[] didCt = Crypto.encryptDid(didKey, Arrays.copyOfRange(remoteInfo, 4, remoteInfo.length));

        Assert.assertEquals("secret", "fac3a6fd591dcea21f9f4fefe297804f49291527ae818b285f4a75a6fab72af8", Util.bytesToHex(secret));
        Assert.assertEquals("derived", "0cf5615003810d89c233a12a8fc5100e31299d80c4c290dc7d33f19ec42ea48a95c5544f105fe7ebb8b39233c6542b1fff90b2206265080bf516365fd8d758fe", Util.bytesToHex(derived));
        Assert.assertEquals("token", "0cf5615003810d89c233a12a", Util.bytesToHex(token));
        Assert.assertEquals("bindKey", "8fc5100e31299d80c4c290dc7d33f19e", Util.bytesToHex(bindKey));
        Assert.assertEquals("didKey", "c42ea48a95c5544f105fe7ebb8b39233", Util.bytesToHex(didKey));
        Assert.assertEquals("didCt", "646735cc7a96373aabbd93afa089bb6cd2d080302101007a", Util.bytesToHex(didCt));
    }

    public void testLogin() {
        byte[] loginKey = Util.hexToBytes("a8699783c1f03c7b73a046cdb613a9bf");

        byte[] token = Util.hexToBytes("0cf5615003810d89c233a12a");
        byte[] remoteLoginKey = Util.hexToBytes("90fdec0ece05016d7f116b50fca4b4bf");

        byte[] remoteLoginInfo = Util.hexToBytes("471467ea7ed6064f8dd72f416c079dcb3bb78e3c94a51e97b98ef7623a7798e5");

        byte[] salt = Util.combineBytes(loginKey, remoteLoginKey);
        byte[] saltInv = Util.combineBytes(remoteLoginKey, loginKey);

        byte[] derived = Crypto.deriveSecret(token, salt=salt);

        byte[] devKey = Arrays.copyOfRange(derived, 0, 16);
        byte[] appKey = Arrays.copyOfRange(derived, 16, 32);
        byte[] devIv = Arrays.copyOfRange(derived, 32, 36);
        byte[] appIv = Arrays.copyOfRange(derived, 36, 40);
        byte[] junk = Arrays.copyOfRange(derived, 40, 64);

        byte[] loginInfo = Crypto.hash(appKey, salt);
        byte[] calcRemoteInfo = Crypto.hash(devKey, saltInv);

        Assert.assertArrayEquals("remoteLoginInfo" , remoteLoginInfo, calcRemoteInfo);

        Assert.assertEquals("derived", "3c2fdae69f8746663a7d91029724b07212a4122dbe3cf60f3bdcb37139c34611cd016050c87de6f171d2ebdcec94f5359e2fd0c907254fe75992107830c2a9d6", Util.bytesToHex(derived));
        Assert.assertEquals("devKey", "3c2fdae69f8746663a7d91029724b072", Util.bytesToHex(devKey));
        Assert.assertEquals("appKey", "12a4122dbe3cf60f3bdcb37139c34611", Util.bytesToHex(appKey));
        Assert.assertEquals("devIv", "cd016050", Util.bytesToHex(devIv));
        Assert.assertEquals("appIv", "c87de6f1", Util.bytesToHex(appIv));
        Assert.assertEquals("loginInfo", "bbb99b6a6f1ae419e3b13db93514f3e12a1843033f276392eea99068affca753", Util.bytesToHex(loginInfo));
    }
}