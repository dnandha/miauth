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
