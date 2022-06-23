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

public class CommandBase {
    static final byte[] ReceiveReady = new byte[]{0, 0, 1, 1};
    static final byte[] Received = new byte[]{0, 0, 1, 0};
    static final byte[] Error = new byte[]{(byte) 0xe0, 0, 0, 0};
    /* RCV_TOUT = b"\x00\x00\x01\x05\x01\x00"
    RCV_ERR = b"\x00\x00\x01\x05\x03\x00"*/
}
