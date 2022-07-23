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

import java.util.Arrays;

public class DataLogin implements IData {
    private final Data parent;
    private final byte[] loginKey;
    private byte[] remoteKey = null;
    private byte[] remoteInfo = null;
    private byte[] ct = null;

    public DataLogin(Data parent, byte[] loginKey) {
        this.parent = parent;
        this.loginKey = loginKey;
    }

    public DataLogin(Data parent) {
        this.parent = parent;
        this.loginKey = Crypto.generateRandomKey();
    }

    @Override
    public boolean calculate() {
        byte[] salt = Util.combineBytes(loginKey, remoteKey);
        byte[] saltInv = Util.combineBytes(remoteKey, loginKey);

        byte[] derived = Crypto.deriveSecret(parent.token, salt);
        byte[] devKey = Arrays.copyOfRange(derived, 0, 16);
        byte[] appKey = Arrays.copyOfRange(derived, 16, 32);
        byte[] devIv = Arrays.copyOfRange(derived, 32, 36);
        byte[] appIv = Arrays.copyOfRange(derived, 36, 40);
        byte[] junk = Arrays.copyOfRange(derived, 40, 50);

        getParent().setKeys(devKey, appKey);
        getParent().setIvs(devIv, appIv);

        byte[] expectedRemoteInfo = Crypto.hash(devKey, saltInv);
        if (!Arrays.equals(expectedRemoteInfo, remoteInfo)) {
            System.err.println("login: unexpected remote info");
            return false;
        }

        ct = Crypto.hash(appKey, salt);
        return true;
    }

    @Override
    public boolean hasMyKey() {
        return this.loginKey != null;
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
        remoteInfo = data;
        return true;
    }

    @Override
    public void setRemoteKey(byte[] data) {
        remoteKey = data;
    }

    @Override
    public byte[] getRemoteKey() {
        return remoteKey;
    }

    @Override
    public byte[] getRemoteInfo() {
        return remoteInfo;
    }

    @Override
    public byte[] getMyKey() {
        return loginKey;
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
        remoteKey = null;
        remoteInfo = null;
    }
}
