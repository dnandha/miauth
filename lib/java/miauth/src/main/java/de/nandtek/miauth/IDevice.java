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

import java.util.UUID;

import io.reactivex.Observable;
import io.reactivex.functions.Consumer;

public interface IDevice {
    void prepare();
    void connect(Consumer<Boolean> onConnect);
    void disconnect();
    boolean isConnected();
    void write(UUID uuid, byte[] data, Consumer<byte[]> onWriteSuccess);
    void read(UUID uuid, Consumer<byte[]> onReadSuccess);
    Observable<byte[]> onNotify(UUID uuid);

    boolean isDisconnected();

    void onDisconnect(Consumer<Boolean> onDisconnect);
}
