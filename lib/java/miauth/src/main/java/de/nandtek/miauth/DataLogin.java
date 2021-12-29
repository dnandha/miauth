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

import java.util.Arrays;

public class DataLogin implements IData {
    private final Data parent;
    private byte[] loginKey = null;
    private byte[] remoteLoginKey = null;
    private byte[] appKey = null;
    private byte[] devKey = null;
    private byte[] appIv = null;
    private byte[] devIv = null;
    private byte[] remoteLoginInfo = null;
    private byte[] ct = null;

    private int it = 0;

    public DataLogin(Data parent, byte[] loginKey) {
        this.parent = parent;
        this.loginKey = loginKey;
    }

    public DataLogin(Data parent) {
        this.parent = parent;
        this.loginKey = Crypto.generateRandomKey();
    }

    @Override
    public void calculate() {
        byte[] salt = Util.combineBytes(loginKey, remoteLoginKey);
        byte[] saltInv = Util.combineBytes(remoteLoginKey, loginKey);

        byte[] derived = Crypto.deriveSecret(parent.token, salt = salt);
        devKey = Arrays.copyOfRange(derived, 0, 16);
        appKey = Arrays.copyOfRange(derived, 16, 32);
        devIv = Arrays.copyOfRange(derived, 32, 36);
        appIv = Arrays.copyOfRange(derived, 36, 40);
        byte[] junk = Arrays.copyOfRange(derived, 40, 50);

        byte[] expectedRemoteInfo = Crypto.hash(devKey, saltInv);

        if (!Arrays.equals(expectedRemoteInfo, remoteLoginInfo)) {
            throw new AssertionError("Unexpected remote info");
        }

        ct = Crypto.hash(appKey, salt);
    }

    @Override
    public boolean hasRemoteInfo() {
        return remoteLoginInfo != null;
    }

    @Override
    public boolean hasRemoteKey() {
        return remoteLoginKey != null;
    }

    @Override
    public void setRemoteInfo(byte[] data) {
        remoteLoginInfo = data;
    }

    @Override
    public void setRemoteKey(byte[] data) {
        remoteLoginKey = data;
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

    public byte[] encryptUart(byte[] msg) {
        return Crypto.encryptUart(appKey, appIv, msg, it++);
    }

    public byte[] decryptUart(byte[] msg) {
        return Crypto.decryptUart(devKey, devIv, msg);
    }
}
