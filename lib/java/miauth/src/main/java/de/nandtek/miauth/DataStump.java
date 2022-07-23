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

public class DataStump implements IData {
    private final Data parent;

    public DataStump(Data parent) {
        this.parent = parent;
    }

    @Override
    public boolean calculate() {
        return false;
    }

    @Override
    public boolean hasMyKey() {
        return false;
    }

    @Override
    public boolean hasRemoteInfo() {
        return false;
    }

    @Override
    public boolean hasRemoteKey() {
        return false;
    }

    @Override
    public boolean setRemoteInfo(byte[] data) { return false; }

    @Override
    public void setRemoteKey(byte[] data) {

    }

    @Override
    public byte[] getRemoteKey() {
        return new byte[0];
    }

    @Override
    public byte[] getRemoteInfo() {
        return new byte[0];
    }

    @Override
    public byte[] getMyKey() {
        return new byte[0];
    }

    @Override
    public byte[] getCt() {
        return new byte[0];
    }

    @Override
    public Data getParent() {
        return parent;
    }

    @Override
    public void clear() {

    }
}
