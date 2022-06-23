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

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Crypto {
    static {
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }


    public static byte[] generateRandomKey() {
        return generateRandomKey(16);
    }

    public static byte[] generateRandomKey(int size) {
        byte[] result = new byte[size];
        new Random().nextBytes(result);
        return result;
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH");
            kpg.initialize(new ECGenParameterSpec("SECP256R1"));
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static PrivateKey generatePrivateKey(byte[] data) {
        return generatePrivateKey(new BigInteger(data));
    }

    public static PrivateKey generatePrivateKey(BigInteger val) {
        ECNamedCurveParameterSpec paramSpec = ECNamedCurveTable.getParameterSpec("SECP256R1");
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(val, paramSpec);

        try {
            KeyFactory kf = KeyFactory.getInstance("ECDH");
            return kf.generatePrivate(keySpec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] privateKeyToBytes(PrivateKey key) {
        return ((ECPrivateKey) key).getD().toByteArray();
    }

    public static byte[] publicKeyToBytes(PublicKey key) {
        byte[] data = ((ECPublicKey) key).getQ().getEncoded(false);
        return Arrays.copyOfRange(data,1, data.length);  // drop first byte (type)
    }

    public static PublicKey generatePublicKey(byte[] key) {
        byte[] pk = new byte[key.length + 1];
        pk[0] = 4;  // set point type
        System.arraycopy(key, 0, pk, 1, key.length);

        ECNamedCurveParameterSpec paramSpec = ECNamedCurveTable.getParameterSpec("SECP256R1");

        ECPoint pt = paramSpec.getCurve().decodePoint(pk);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(pt, paramSpec);

        try {
            KeyFactory kf = KeyFactory.getInstance("ECDH");
            return kf.generatePublic(keySpec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] generateSecret(PrivateKey privateKey, PublicKey publicKey) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(privateKey);
            ka.doPhase(publicKey, true);
            return ka.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return  null;
    }

    public static byte[] hash(byte[] key, byte[] data) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] deriveSecret(byte[] secret, byte[] salt) {
        byte[] result = new byte[64];

        byte[] info = salt != null ? "mible-login-info".getBytes() : "mible-setup-info".getBytes();

        HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
        HKDFParameters params = new HKDFParameters(secret, salt, info);
        generator.init(params);

        generator.generateBytes(result, 0, result.length);
        return result;
    }

    public static byte[] encrypt(byte[] key, byte[] data, byte[] nonce, byte[] aad) {
        return aesCcm(key, data, nonce, aad, Cipher.ENCRYPT_MODE);
    }
    public static byte[] decrypt(byte[] key, byte[] data, byte[] nonce, byte[] aad) {
        return aesCcm(key, data, nonce, aad, Cipher.DECRYPT_MODE);
    }
    public static byte[] aesCcm(byte[] key, byte[] data, byte[] nonce, byte[] aad, int mode) {
        GCMParameterSpec paramSpec = new GCMParameterSpec(4 * 8, nonce);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        try {
            Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding");
            cipher.init(mode, keySpec, paramSpec);
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] encryptDid(byte[] key, byte[] data) {
        byte[] aad = "devID".getBytes();
        byte[] nonce = new byte[12];
        for (int j = 0, i = 16; i <= 27; i++, j++) nonce[j] = (byte) i;

        return encrypt(key, data, nonce, aad);
    }

    public static byte[] encryptUart(byte[] key, byte[] iv, byte[] msg, int it) {
        byte[] randBytes = generateRandomKey(4);
        return encryptUart(key, iv, msg, it, randBytes);
    }

    public static byte[] encryptUart(byte[] key, byte[] iv, byte[] msg, int it, byte[] randBytes) {
        if (iv == null) {
            return encryptUartWeak(key, msg, randBytes);
        }

        byte[] itBytes = Util.intToBytes(it, 4);
        byte[] zeroBytes = new byte[]{0,0,0,0};
        byte size = msg[2];

        byte[] data = new byte[msg.length-3+randBytes.length];
        byte[] nonce = new byte[iv.length+zeroBytes.length+itBytes.length];

        System.arraycopy(msg, 3, data, 0, msg.length-3);
        System.arraycopy(randBytes, 0, data, msg.length-3, randBytes.length);

        System.arraycopy(iv, 0, nonce, 0, iv.length);
        System.arraycopy(zeroBytes, 0, nonce, iv.length, zeroBytes.length);
        System.arraycopy(itBytes, 0, nonce, iv.length+zeroBytes.length, itBytes.length);

        byte[] ct = encrypt(key, data, nonce, null);

        byte[] header = new byte[] {0x55, (byte) 0xab};
        data = new byte[1+2+ct.length];
        data[0] = size;
        data[1] = itBytes[0];
        data[2] = itBytes[1];
        System.arraycopy(ct, 0, data, 3, ct.length);

        byte[] crc = Util.crc(data, 2);

        byte[] result = new byte[header.length+data.length+crc.length];
        System.arraycopy(header, 0, result, 0, header.length);
        System.arraycopy(data, 0, result, header.length, data.length);
        System.arraycopy(crc, 0, result, header.length+data.length, crc.length);

        return result;
    }

    public static byte[] decryptUart(byte[] key, byte[] iv, byte[] msg) {
        if (iv == null) {
            return decryptUartWeak(key, msg);
        }

        byte[] it = new byte[2];
        it[0] = msg[3];
        it[1] = msg[4];

        byte[] nonce = new byte[iv.length+4+it.length+2];
        System.arraycopy(iv, 0, nonce, 0, iv.length);
        System.arraycopy(it, 0, nonce, iv.length+4, it.length);

        byte[] ct = new byte[msg.length-2-5];
        System.arraycopy(msg, 5, ct, 0, ct.length);

        byte[] result = decrypt(key, ct, nonce, null);
        return Arrays.copyOfRange(result, 0, result.length - 4);
    }

    public static byte[] encryptUartWeak(byte[] key, byte[] msg, byte[] randBytes) {
        byte[] nMsg = new byte[msg.length + randBytes.length];
        System.arraycopy(msg, 0, nMsg, 0, msg.length);
        //byte[] nMsg = Util.combineBytes(msg, randBytes);
        byte[] ct = new byte[nMsg.length-3];
        for (int i = 0; i < nMsg.length-3; i++) {
            ct[i] = (byte) (nMsg[i+3] ^ (i < key.length ? key[i] : 0));
        }

        byte[] header = new byte[] {0x55, (byte) 0xab};
        byte[] data = Util.combineBytes(new byte[]{nMsg[2]}, ct);
        byte[] crc = Util.crc(data, 2);

        byte[] result = new byte[header.length+data.length+crc.length];
        System.arraycopy(header, 0, result, 0, header.length);
        System.arraycopy(data, 0, result, header.length, data.length);
        System.arraycopy(crc, 0, result, header.length+data.length, crc.length);

        return result;
    }

    public static byte[] decryptUartWeak(byte[] key, byte[] msg) {
        byte[] result = new byte[msg.length-3];
        for (int i = 0; i < msg.length-3; i++) {
            result[i] = (byte) (msg[i+3] ^ (i < key.length ? key[i] : 0));
        }

        return Arrays.copyOfRange(result, 0, result.length-6);
    }
}
