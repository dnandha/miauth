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
    public void setRemoteInfo(byte[] data) {
        remoteInfo = data;
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