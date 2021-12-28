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

public class CommandRegister extends CommandBase {
    static final byte[] GetInfo = new byte[]{(byte) 0xa2, 0, 0, 0};
    static final byte[] AuthConfirmed = new byte[]{0x11, 0, 0, 0};
    static final byte[] AuthDenied = new byte[]{0x12, 0, 0, 0};
    static final byte[] AuthRequest = new byte[]{0x13, 0, 0, 0};
    static final byte[] KeyExchange = new byte[]{0x15, 0, 0, 0};
    static final byte[] SendingCt = new byte[]{0, 0, 0, 0, 2, 0};
    static final byte[] SendingKey = new byte[]{0, 0, 0, 3, 4, 0};
}
