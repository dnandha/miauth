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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.UUID;

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
        StringBuilder hex = new StringBuilder();

        // Iterating through each byte in the array
        for (byte i : byteArray) {
            hex.append(String.format("%02X", i));
        }

        return hex.toString().toLowerCase();
    }

    public static int bytesToInt(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        if (bytes.length == 1) {
            return bb.get();
        } else if (bytes.length == 2) {
            return bb.getShort();
        } else if (bytes.length == 4) {
            return bb.getInt();
        }
        return 0;
        //int result = bytes[0] & 0xff;
        //for (int i = 1; i < bytes.length; i++) {
        //    result |= (bytes[i] & 0xff) << 8;
        //}
        //return result;
    }

    public static int signedToUnsignedInt(short val) {
        short result = val;
        // ss the negative-bit set?
        if ((val & 0x8FFF) > 0) {
            // flip
            result = (short) ~result;
            // +1
            result += 1;

            result = (short) -result;
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
        sum = ~sum;

        return intToBytes(sum, 2);
    }

    public static String randomAscii(int size) {
        UUID randomUUID = UUID.randomUUID();
        return randomUUID.toString().replaceAll("_", "").replaceAll("-","").substring(0, size);
    }
}
