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
package de.nandtek.nbauth;

import de.nandtek.miauth.CommandBase;
import de.nandtek.miauth.Util;

public class CommandLogin extends CommandBase {
    static final byte[] CmdInit = Util.hexToBytes("5AA5003D215B00");
    static final byte[] CmdPing(byte[] rand) {
        return Util.combineBytes(Util.hexToBytes("5AA5103D215C00"), rand);
    }
    static final byte[] CmdPair(byte[] serial) {
        return Util.combineBytes(Util.hexToBytes("5AA50E3D215D00"), serial);
    }
    static final byte[] AckInit = Util.hexToBytes("5AA51E213D5B01");
    static final byte[] AckPre = Util.hexToBytes("5AA500213D5C00");
    static final byte[] AckPing = Util.hexToBytes("5AA500213D5C01");
    static final byte[] AckPair = Util.hexToBytes("5AA500213D5D01");
}
