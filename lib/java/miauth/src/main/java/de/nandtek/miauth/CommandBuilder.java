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

// TODO: implement m365 command builder
public class CommandBuilder {
    public static byte[] GetSerialNo = new byte[]{0x55, (byte)0xaa, 0x03, 0x20, 0x01, 0x10, 0x0e};
}
