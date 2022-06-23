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

public class CommandLogin extends CommandBase {
    static final byte[] Request = new byte[]{(byte) 0x24, 0, 0, 0};
    static final byte[] AuthConfirmed = new byte[]{0x21, 0, 0, 0};
    static final byte[] AuthDenied = new byte[]{0x23, 0, 0, 0};
    static final byte[] SendingCt = new byte[]{0, 0, 0, 0x0a, 2, 0};
    static final byte[] SendingKey = new byte[]{0, 0, 0, 0x0b, 1, 0};
    static final byte[] RespondKey = new byte[]{0, 0, 0, 0x0d, 1, 0};
    static final byte[] RespondInfo = new byte[]{0, 0, 0, 0x0c, 2, 0};
}
