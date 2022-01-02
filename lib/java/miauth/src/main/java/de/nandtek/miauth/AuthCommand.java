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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import io.reactivex.Observable;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;

public class AuthCommand extends AuthBase {
    private final byte[] command;
    private final Consumer<byte[]> onResponse;

    public AuthCommand(IDevice device, DataLogin data, byte[] command, Consumer<byte[]> onResponse) {
        super(device, data);
        this.command = command;
        this.onResponse = onResponse;
    }

    @Override
    protected void handleMessage(byte[] message) {
        byte[] response = null;

        if (message != null) {
            System.out.println("command: handling message " + Util.bytesToHex(message));

            byte[] dec = ((DataLogin) data).decryptUart(message);
            System.out.println("command: decoded message:" + Util.bytesToHex(dec));
            response = Arrays.copyOfRange(dec, 3, dec.length - 4);
        }

        try {
            stopNotifyTrigger.onNext(true);
            //compositeDisposable.dispose();

            onResponse.accept(response);
        } catch (Exception e) {
            System.err.println("command: handle message error - " + e.getMessage());
        }
    }

    @Override
    public void exec() {
        final Disposable rxSub = device.onNotify(MiUUID.RX)
                .doOnError(throwable -> handleMessage(null))
                .takeUntil(stopNotifyTrigger)
                .timeout(2, TimeUnit.SECONDS, Observable.create(emitter -> {
                    System.out.println("command: subscription timeout");
                    //stopNotifyTrigger.onNext(true);

                    byte[] message = null;
                    if (receiveBuffer != null && !receiveBuffer.hasRemaining()) {
                        message = new byte[receiveBuffer.position()];
                        receiveBuffer.position(0);
                        receiveBuffer.get(message);
                    }
                    handleMessage(message);
                }))
                .subscribe(
                        this::receiveParcel,
                        Throwable::printStackTrace
                    );
        compositeDisposable.add(rxSub);

        System.out.println("command: writing " + Util.bytesToHex(command));
        writeChunked(command);
    }

    @Override
    protected void receiveParcel(byte[] data) {
        if (data == null || data.length == 0) {
            System.out.println("command: recv empty data");
            return;
        }

        System.out.println("command: recv message "+ Util.bytesToHex(data));
        if ((data[0] & 0xff) == 0x55 && (data[1] & 0xff) != 0xaa && data.length > 2) {
            receiveBuffer = ByteBuffer.allocate(0x10 + data[2]);
            receiveBuffer.put(data);
        } else {
            receiveBuffer.put(data);
        }

        if (!receiveBuffer.hasRemaining()) {
            // handle this on timeout to avoid double subscriptions
        }
    }

    private void writeChunked(byte[] cmd) {
        ByteBuffer buf = ByteBuffer.wrap(((DataLogin)data).encryptUart(cmd));
        while (buf.remaining() > 0) {
            int len = Math.min(buf.remaining(), ChunkSize+2);
            byte[] chunk = new byte[len];
            buf.get(chunk, 0, len);

            write(MiUUID.TX, chunk);
        }
    }
}
