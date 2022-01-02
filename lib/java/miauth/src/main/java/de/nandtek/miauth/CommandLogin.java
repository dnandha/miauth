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

public class CommandLogin extends CommandBase {
    static final byte[] Request = new byte[]{(byte) 0x24, 0, 0, 0};
    static final byte[] AuthConfirmed = new byte[]{0x21, 0, 0, 0};
    static final byte[] AuthDenied = new byte[]{0x23, 0, 0, 0};
    static final byte[] SendingCt = new byte[]{0, 0, 0, 0x0a, 2, 0};
    static final byte[] SendingKey = new byte[]{0, 0, 0, 0x0b, 1, 0};
    static final byte[] RespondKey = new byte[]{0, 0, 0, 0x0d, 1, 0};
    static final byte[] RespondInfo = new byte[]{0, 0, 0, 0x0c, 2, 0};
}
