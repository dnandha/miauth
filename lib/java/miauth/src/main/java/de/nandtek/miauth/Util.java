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

public class Util {
    public static byte[] combineBytes(byte[] b1, byte[] b2) {
        byte[] result = new byte[b1.length+b2.length];
        System.arraycopy(b1, 0, result, 0, b1.length);
        System.arraycopy(b2, 0, result, b1.length, b2.length);

        return result;
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bytesToHex(byte[] byteArray)
    {
        String hex = "";

        // Iterating through each byte in the array
        for (byte i : byteArray) {
            hex += String.format("%02X", i);
        }

        return hex.toLowerCase();
    }

    public static int bytesToInt(byte[] bytes) {
        //ByteBuffer bb = ByteBuffer.wrap(bytes);
        //bb.order(ByteOrder.LITTLE_ENDIAN);
        //if (bytes.length == 1) {
        //    return bb.getChar();
        //} else if (bytes.length == 2) {
        //    return bb.getShort();
        //} else if (bytes.length == 4) {
        //    return bb.getInt();
        //}
        //return 0;
        int result = bytes[0] & 0xff;
        for (int i = 1; i < bytes.length; i++) {
            result |= (bytes[i] & 0xff) << 8;
        }
        return result;
    }

    public static byte[] intToBytes(int i, int size) {
        //byte[] result = new byte[size];
        //ByteBuffer bb = ByteBuffer.allocate(size);
        //bb.order(ByteOrder.LITTLE_ENDIAN);
        //if (size == 1) {
        //    bb.putChar((char) i);
        //} else if (size == 2) {
        //    bb.putShort((short) i);
        //} else if (size == 4) {
        //    bb.putInt(i);
        //}
        //bb.position(0).get(result);
        //return result;
        byte[] result = new byte[size];
        for (int j = 0; j < size; j++) {
            result[j] = (byte)((i >> (j * 8)) & 0xff);
        }
        return result;
    }

    public static byte[] crc16(byte[] data) {
        int sum = 0;
        for (byte datum : data) sum += (datum & 0xff);
        System.out.println(sum);
        sum = ~sum;

        return intToBytes(sum, 2);
    }
}
