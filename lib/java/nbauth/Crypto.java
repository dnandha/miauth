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
//
//  This class is my Java port of https://github.com/scooterhacking/NinebotCrypto
//  Huge thanks to the original authors for sharing their work!
//

package de.nandtek.nbauth;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import de.nandtek.miauth.Util;

public class Crypto
{
    private byte[] name;
    private final byte[] dataBasic = Util.hexToBytes("97cfb802844143de56002b3b34780a5d");
    private final byte[] appData = new byte[16];
    private final byte[] bleData = new byte[16];
    private final byte[] shaKey = new byte[16];
    private int msgIt = 0;

    public Crypto() {
    }

    public Crypto(String name) {
        this.name = name.getBytes();
        this.calcSha1Key(this.name, dataBasic);
    }

    public byte[] getShaKey() {
        return shaKey;
    }

    public void setShaKey(byte[] key) {
        System.arraycopy(key, 0, shaKey, 0, shaKey.length);
    }

    public void setName(byte[] name) {
        this.name = name;
        this.calcSha1Key(this.name, dataBasic);
    }

    public void setBleData(byte[] bleData) {
        System.arraycopy(bleData, 0, this.bleData, 0, 16);
        calcSha1Key(name, this.bleData);
    }

    public void setAppData(byte[] appData) {
        System.arraycopy(appData, 0, this.appData, 0, 16);
        calcSha1Key(this.appData, bleData);
    }

    private byte[] aesEcbEncrypt(byte[] data, final byte[] key) {
        final SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        final Cipher instance;
        try {
            instance = Cipher.getInstance("AES/ECB/PKCS5Padding");
            instance.init(1, secretKeySpec);
            return instance.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }
    
    private byte[] calcCrcFirstMsg(final byte[] data) {
        final int length = data.length;
        long n = 0L;
        byte b;
        for (int i = 0; i < length; ++i, n += b) {
            b = data[i];
        }
        final long n2 = ~n;
        return new byte[] { (byte)(n2 & 0xFFL), (byte)(n2 >> 8 & 0xFFL) };
    }
    
    private byte[] calcCrcNextMsg(final byte[] data, int i) {
        final byte[] aesEncData = new byte[16];
        int length = data.length - 3;
        final byte[] xorData2 = new byte[16];

        aesEncData[0] = 89;
        aesEncData[1] = (byte)((0xFF000000 & i) >> 24);
        aesEncData[2] = (byte)((0xFF0000 & i) >> 16);
        aesEncData[3] = (byte)((0xFF00 & i) >> 8);
        aesEncData[4] = (byte)((i & 0xFF));
        System.arraycopy(this.bleData, 0, aesEncData, 5, 8);
        aesEncData[15] = (byte)length;
        System.arraycopy(Objects.requireNonNull(this.aesEcbEncrypt(aesEncData, this.shaKey)), 0, xorData2, 0, 16);

        byte[] xorData1 = new byte[16];
        System.arraycopy(data, 0, xorData1, 0, 3);
        System.arraycopy(Objects.requireNonNull(this.aesEcbEncrypt(this.createXor(xorData1, xorData2), this.shaKey)), 0, xorData2, 0, 16);

        int n = 3;
        int n2;
        for (i = length; i > 0; i -= n2, n += n2) {
            n2 = Math.min(i, 16);
            xorData1 = new byte[16];
            System.arraycopy(data, n, xorData1, 0, n2);
            System.arraycopy(Objects.requireNonNull(this.aesEcbEncrypt(this.createXor(xorData1, xorData2), this.shaKey)), 0, xorData2, 0, 16);
        }
        aesEncData[0] = 1;
        aesEncData[15] = 0;
        System.arraycopy(Objects.requireNonNull(this.aesEcbEncrypt(aesEncData, this.shaKey)), 0, xorData1, 0, 4);
        return this.createXor(xorData1, xorData2);
    }
    
    private void calcSha1Key(final byte[] b1, final byte[] b2) {
        final byte[] shaData = new byte[32];
        System.arraycopy(b1, 0, shaData, 0, b1.length);
        System.arraycopy(b2, 0, shaData, 16, b2.length);
        System.arraycopy(Objects.requireNonNull(this.sha1(shaData)), 0, this.shaKey, 0, 16);
    }
    
    private byte[] createXor(final byte[] b1, final byte[] b2) {
        final byte[] xorData = b1.clone();
        for (int length = b1.length, i = 0, n = 0; i < length; ++i, ++n) {
            xorData[n] = (byte)(b1[i] ^ b2[n]);
        }
        return xorData;
    }
    
    private byte[] cryptoFirst(final byte[] data) {
        final byte[] result = new byte[data.length];
        int i = data.length;
        final byte[] xorData1 = new byte[16];
        final byte[] xorData2 = new byte[16];
        int n2;
        for (int n = 0; i > 0; i -= n2, n += n2) {
            n2 = Math.min(i, 16);
            System.arraycopy(data, n, xorData1, 0, n2);
            System.arraycopy(Objects.requireNonNull(this.aesEcbEncrypt(this.dataBasic, this.shaKey)), 0, xorData2, 0, 16);
            System.arraycopy(this.createXor(xorData1, xorData2), 0, result, n, n2);
        }
        return result;
    }
    
    private byte[] cryptoNext(final byte[] data, int i) {
        final byte[] result = new byte[data.length];
        final byte[] aesEncData = new byte[16];
        for (int j = 0; j < 16; ++j) {
            aesEncData[j] = 0;
        }
        aesEncData[0] = 1;
        aesEncData[1] = (byte) ((0xFF000000 & i) >> 24);
        aesEncData[2] = (byte) ((0xFF0000 & i) >> 16);
        aesEncData[3] = (byte) ((0xFF00 & i) >> 8);
        aesEncData[4] = (byte) (i & 0xFF);
        System.arraycopy(this.bleData, 0, aesEncData, 5, 8);
        aesEncData[15] = 0;
        i = data.length;
        final byte[] xorData1 = new byte[16];
        final byte[] xorData2 = new byte[16];
        int n2;
        for (int n = 0; i > 0; i -= n2, n += n2) {
            ++aesEncData[15];
            n2 = Math.min(i, 16);
            System.arraycopy(data, n, xorData1, 0, n2);
            System.arraycopy(Objects.requireNonNull(this.aesEcbEncrypt(aesEncData, this.shaKey)), 0, xorData2, 0, 16);
            System.arraycopy(this.createXor(xorData1, xorData2), 0, result, n, n2);
        }
        return result;
    }
    
    private byte[] sha1(byte[] data) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA1");
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    public final byte[] decrypt(byte[] data) {
        final byte[] result = new byte[data.length - 6];
        System.arraycopy(data, 0, result, 0, 3);

        final int newMsgIt = (this.msgIt & 0xFFFF0000)
                + ((int)(((long)data[data.length - 2] & 0xFFL) << 8)) + (data[data.length - 1] & 0xFF);

        final int n = data.length - 9;
        final byte[] payload = new byte[n];
        System.arraycopy(data, 3, payload, 0, n);
        if (newMsgIt == 0) {
            data = this.cryptoFirst(payload);
            System.arraycopy(data, 0, result, 3, data.length);
            //if (array[0] == 90 && array[1] == -91 && array[2] == 30 && array[3] == 33 && array[4] == 62 && array[5] == 91) {
            //    System.arraycopy(array, 7, this.bleData, 0, 16);
            //    this.calcSha1Key(name, this.bleData);
            //}
        }
        else {
            data = this.cryptoNext(payload, newMsgIt);
            System.arraycopy(data, 0, result, 3, data.length);
            if (result[0] == 90 && result[1] == -91 && result[2] == 0 && result[3] == 33 && result[4] == 62 && result[5] == 92 && result[6] == 1) {
                this.calcSha1Key(this.appData, this.bleData);
            }
            if (this.msgIt > newMsgIt) {
                this.msgIt = newMsgIt;
            }
        }
        return result;
    }
    
    public final byte[] encrypt(byte[] data) {
        final byte[] result = new byte[152];
        System.arraycopy(data, 0, result, 0, 3);
        final int n = data.length - 3;
        final byte[] payload = new byte[n];
        System.arraycopy(data, 3, payload, 0, n);
        final int msgIt = this.msgIt;
        if (msgIt == 0) {
            data = this.calcCrcFirstMsg(payload);
            final byte[] cryptoFirst = this.cryptoFirst(payload);
            System.arraycopy(cryptoFirst, 0, result, 3, cryptoFirst.length);
            result[n + 4] = (result[n + 3] = 0);
            result[n + 5] = data[0];
            result[n + 6] = data[1];
            result[n + 8] = (result[n + 7] = 0);
            data = Arrays.copyOfRange(result, 0, n + 9);
            this.msgIt++;
        }
        else {
            this.msgIt++;
            final byte[] calcCrcNextMsg = this.calcCrcNextMsg(data, this.msgIt);
            final byte[] cryptoNext = this.cryptoNext(payload, this.msgIt);
            System.arraycopy(cryptoNext, 0, result, 3, cryptoNext.length);
            result[n + 3] = calcCrcNextMsg[0];
            result[n + 4] = calcCrcNextMsg[1];
            result[n + 5] = calcCrcNextMsg[2];
            result[n + 6] = calcCrcNextMsg[3];
            result[n + 7] = (byte) ((this.msgIt & 0xFF00) >> 8);
            result[n + 8] = (byte) (this.msgIt & 0xFF);
            //if (data[0] == 90 && data[1] == -91 && data[2] == 16 && data[3] == 62 && data[4] == 33 && data[5] == 92 && data[6] == 0) {
            //    System.arraycopy(data, 7, this.appData, 0, 16);
            //}
            data = Arrays.copyOfRange(result, 0, n + 9);
        }
        return data;
    }
}
