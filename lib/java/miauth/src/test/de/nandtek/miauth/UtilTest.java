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

    public void testCrc16() {
        byte[] crc = Util.crc16(new byte[]{(byte)0xa1,0x21,(byte)0xf3,4,5,6,7,8,9});
        Assert.assertEquals("23fe", Util.bytesToHex(crc));
    }
}