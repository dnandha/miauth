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
        parent.setBltId(remoteInfo);
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
    public void setRemoteInfo(byte[] data) {
        remoteInfo = Arrays.copyOfRange(data, 4, data.length);
        if (remoteInfo.length < 20) {
            remoteInfo = parent.getBltId();
            if (remoteInfo == null) {
                remoteInfo = new byte[20];

                String bltid = "blt.4.1" + Util.randomAscii(10) + "00";
                System.arraycopy(bltid.getBytes(), 0, remoteInfo, 1, 19);
            }
        }
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
