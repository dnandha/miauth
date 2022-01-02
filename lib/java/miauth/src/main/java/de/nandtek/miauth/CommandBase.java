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

public class CommandBase {
    static final byte[] ReceiveReady = new byte[]{0, 0, 1, 1};
    static final byte[] Received = new byte[]{0, 0, 1, 0};
    /* RCV_TOUT = b"\x00\x00\x01\x05\x01\x00"
    RCV_ERR = b"\x00\x00\x01\x05\x03\x00"*/
}
