//
// MiAuth - Authenticate and interact with Xiaomi devices over BLE
// Copyright (C) 2021  Daljeet Nandha
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
package de.nandtek.miauth;

import junit.framework.TestCase;

import org.junit.Assert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DataTest extends TestCase {

    public void testSetRemoteInfo() {
        IData data = new DataRegister(null);
        byte[] remoteInfo = Util.hexToBytes("0100000000626c742e342e31386e35383236366b67673030");
        data.setRemoteInfo(remoteInfo);
    }

    public void testSetRemoteKey() {
        IData data = new DataRegister(null);
        byte[] remoteKey = Util.hexToBytes("a9775081e377a96bf3a2372c7d10f47bcf083e1f0d50f505e6a2bc4d80da6dfe164ecf4d9cebbf6830854481b7cf7acd002f0bbde231fb0339bf9bcd4d6d9598");
        data.setRemoteKey(remoteKey);
    }

    public void testCalculateRegister() {
        BigInteger privKeyD = new BigInteger("48461508383982493215332654270464913273532832436436077476553357014100094140803");
        PrivateKey privKey = Crypto.generatePrivateKey(privKeyD);
        byte[] pubKeyD = Util.hexToBytes("4925e4cf05129fa65116a4a324fc86eefd4cd176717f0938ccbd2387fd52d0efd85162c20c0fcc72ca85a8b18f61ef980a70e1a6e7ff15f5289881ee59b8f4af");
        PublicKey pubKey = Crypto.generatePublicKey(pubKeyD);

        IData data = new DataRegister(new Data(), new KeyPair(pubKey, privKey));

        byte[] remoteInfo = Util.hexToBytes("0100000000626c742e342e31386e35383236366b67673030");
        byte[] remotePubKeyD = Util.hexToBytes("2afe2a8c1c56e5e70721665cd20d017273111ecaeceb1e4d641e7b7a122a9c3041e5cbc962eefbdb155ffd95847a0d8762803291fc2866c5672ceee0e77d77fc");

        data.setRemoteInfo(remoteInfo);
        data.setRemoteKey(remotePubKeyD);
        data.calculate();

        byte[] didCt = data.getCt();
        byte[] token = data.getParent().getToken();

        Assert.assertEquals("didCt", "646735cc7a96373aabbd93afa089bb6cd2d080302101007a", Util.bytesToHex(didCt));
        Assert.assertEquals("token", "0cf5615003810d89c233a12a", Util.bytesToHex(token));
    }

    public void testCalculateLogin() {
        byte[] randomKey = Util.hexToBytes("a8699783c1f03c7b73a046cdb613a9bf");
        IData data = new DataLogin(new Data(), randomKey);

        data.getParent().setToken(Util.hexToBytes("0cf5615003810d89c233a12a"));
        data.setRemoteKey(Util.hexToBytes("90fdec0ece05016d7f116b50fca4b4bf"));
        data.setRemoteInfo(Util.hexToBytes("471467ea7ed6064f8dd72f416c079dcb3bb78e3c94a51e97b98ef7623a7798e5"));

        byte[] ct = data.getCt();
        Assert.assertEquals("loginInfo", "bbb99b6a6f1ae419e3b13db93514f3e12a1843033f276392eea99068affca753", Util.bytesToHex(ct));
    }
}