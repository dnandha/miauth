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

import android.os.Debug;

import junit.framework.TestCase;

import org.junit.Assert;

public class UtilTest extends TestCase {

    public void testCombineBytes() {
        byte[] b1 = Util.hexToBytes("01020304");
        byte[] b2 = Util.hexToBytes("05060708");
        byte[] comb = Util.combineBytes(b1, b2);
        Assert.assertArrayEquals(new byte[]{1,2,3,4,5,6,7,8}, comb);
    }

    public void testHexToBytes() {
        byte[] b = Util.hexToBytes("01020304");
        Assert.assertArrayEquals(new byte[]{1,2,3,4}, b);
    }

    public void testBytesToHex() {
        String hex = Util.bytesToHex(new byte[]{1,2,3,4});
        Assert.assertEquals("01020304", hex);
    }

    public void testIntToBytes() {
        byte[] b = Util.intToBytes(1337, 4);
        Assert.assertArrayEquals(new byte[]{0x39,5,0,0}, b);
    }

    public void testByteToInt() {
        int i = Util.bytesToInt(new byte[]{0x39});
        Assert.assertEquals(57, i);
    }

    public void testBytesToInt() {
        int i = Util.bytesToInt(new byte[]{0x39,5,0,0});
        Assert.assertEquals(1337, i);
    }

    public void testBytesTo32Int() {
        int i = Util.bytesToInt(new byte[]{0x39,5,1,0});
        Assert.assertEquals(66873, i);
    }

    public void testCrc16() {
        byte[] crc = Util.crc(new byte[]{(byte)0xa1,0x21,(byte)0xf3,4,5,6,7,8,9}, 2);
        Assert.assertEquals("23fe", Util.bytesToHex(crc));
    }

    public void testCrc32() {
        byte[] b = new byte[]{
                (byte)0xa1,0x21,(byte)0xf3,4,5,6,7,8,9,
                (byte)0xa1,0x21,(byte)0xf3,4,5,6,7,8,9
        };
        byte[] crc = Util.crc(b, 4);
        Assert.assertEquals("23fe23fe", Util.bytesToHex(crc));
    }

    public void testUnsignedToSignedInt() {
        int val = 33023;
        Assert.assertEquals(-32513, Util.signedToUnsignedInt((short) val));
        // not
        val = 32512;
        Assert.assertEquals(val, Util.signedToUnsignedInt((short) val));
    }

    public void testRandomAscii() {
        String str = Util.randomAscii(8);
        Assert.assertEquals(8, str.length());
    }

    public void testIntToHex() {
        Assert.assertEquals("D5", Util.intToHex(213));
    }
}