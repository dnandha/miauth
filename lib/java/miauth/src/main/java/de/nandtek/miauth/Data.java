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
        if (appKey == null) {
            byte[] crc = Util.crc(Arrays.copyOfRange(msg, 2, msg.length), 2);
            return Util.combineBytes(msg, crc);
        }
        return Crypto.encryptUart(appKey, appIv, msg, it++);
    }

    public byte[] decryptUart(byte[] msg) {
        if (devKey == null) {
            return Arrays.copyOfRange(msg, 3, msg.length - 2);
        }
        return Crypto.decryptUart(devKey, devIv, msg);
    }
}
