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

public class Data {
    protected byte[] token = null;
    protected byte[] bltid = null;
    private byte[] appKey = null;
    private byte[] devKey = null;
    private byte[] appIv = null;
    private byte[] devIv = null;

    private int it = 0;

    public Data() {
    }

    public boolean hasToken() {
        return token != null;
    }

    public byte[] getToken() {
        return token;
    }

    public void setToken(byte[] data) {
        token = data;
    }

    public byte[] getBltId() {
        return bltid;
    }

    public void setBltId(byte[] bltid) {
        this.bltid = bltid;
    }

    public boolean hasBltId() {
        return bltid != null;
    }

    public void resetToken() {
        this.token = null;
    }

    public void resetKeys() {
        this.devKey = null;
        this.appKey = null;
        this.devIv = null;
        this.appIv = null;
    }

    public void setKeys(byte[] devKey, byte[] appKey) {
        this.devKey = devKey;
        this.appKey = appKey;
    }

    public void setIvs(byte[] devIv, byte[] appIv) {
        this.devIv = devIv;
        this.appIv = appIv;
    }

    public boolean hasKeys() {
        return appKey != null && devKey != null;
    }

    public boolean hasIvs() {
        return appIv != null && devIv != null;
    }

    public byte[] encryptUart(byte[] msg) {
        if (appKey == null || appIv == null) {
            return new byte[0]; // todo
        }
        return Crypto.encryptUart(appKey, appIv, msg, it++);
    }

    public byte[] decryptUart(byte[] msg) {
        if (devKey == null || devIv == null) {
            return new byte[0]; // todo
        }
        return Crypto.decryptUart(devKey, devIv, msg);
    }
}
