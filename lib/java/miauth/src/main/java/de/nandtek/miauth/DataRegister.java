//
//  MiAuth - Authenticate and interact with Xiaomi devices over BLE
//  Copyright (C) 2022  Daljeet Nandha
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as
//  published by the Free Software Foundation, either version 3 of the
//  License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
package de.nandtek.miauth;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

public class DataRegister implements IData {
    private final Data parent;

    private final KeyPair myKeys;
    private byte[] remoteInfo = null;
    private PublicKey remoteKey = null;
    private byte[] ct = null;

    public DataRegister(Data parent, KeyPair kp) {
        this.parent = parent;
        this.myKeys = kp;
    }

    public DataRegister(Data parent) {
        this.parent = parent;
        this.myKeys = Crypto.generateKeyPair();
    }

    @Override
    public boolean calculate() {
        byte[] derived = Crypto.deriveSecret(
                Crypto.generateSecret(myKeys.getPrivate(), remoteKey),
                null);
        parent.setToken(Arrays.copyOfRange(derived, 0, 12));
        byte[] bindKey = Arrays.copyOfRange(derived, 12, 28);
        byte[] didKey = Arrays.copyOfRange(derived, 28, 44);
        byte[] junk = Arrays.copyOfRange(derived, 44, 64);

        ct = Crypto.encryptDid(didKey, remoteInfo);
        return true;
    }

    @Override
    public boolean hasMyKey() {
        return myKeys != null;
    }

    @Override
    public boolean hasRemoteInfo() {
        return remoteInfo != null;
    }

    @Override
    public boolean hasRemoteKey() {
        return remoteKey != null;
    }

    @Override
    public boolean setRemoteInfo(byte[] data) {
        remoteInfo = Arrays.copyOfRange(data, 4, data.length);
        if (remoteInfo.length < 20) {
            remoteInfo = parent.getBltId();
            //remoteInfo = new byte[20];
            //String bltid = "blt.4.1" + Util.randomAscii(10) + "00";
            //System.arraycopy(bltid.getBytes(), 0, remoteInfo, 1, 19);
        }
        parent.setBltId(remoteInfo);

        return remoteInfo != null;
    }

    @Override
    public void setRemoteKey(byte[] data) {
        remoteKey = Crypto.generatePublicKey(data);
    }

    @Override
    public byte[] getRemoteKey() {
        return remoteKey.getEncoded();
    }

    @Override
    public byte[] getRemoteInfo() {
        return remoteInfo;
    }

    @Override
    public byte[] getMyKey() {
        return Crypto.publicKeyToBytes(myKeys.getPublic());
    }

    @Override
    public byte[] getCt() {
        if (ct == null) {
            calculate();
        }
        return ct;
    }

    @Override
    public Data getParent() {
        return parent;
    }

    @Override
    public void clear() {
        remoteInfo = null;
        remoteKey = null;
    }
}
