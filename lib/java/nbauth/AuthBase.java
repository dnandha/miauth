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

import java.nio.ByteBuffer;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import de.nandtek.miauth.IData;
import de.nandtek.miauth.IDevice;
import de.nandtek.miauth.MiUUID;
import de.nandtek.miauth.Util;
import io.reactivex.Observable;
import io.reactivex.disposables.CompositeDisposable;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;
import io.reactivex.subjects.PublishSubject;

public class AuthBase {
    public static int ChunkSize = 20;
    protected final Crypto crypto;
    protected IDevice device;
    protected final IData data;
    protected ByteBuffer receiveBuffer;
    protected ByteBuffer sendBuffer;
    protected final CompositeDisposable compositeDisposable = new CompositeDisposable();
    protected final PublishSubject<Boolean> stopNotifyTrigger = PublishSubject.create();

    private final Semaphore writePossible = new Semaphore(1, true);

    protected Consumer<Boolean> onWritten = null;

    public AuthBase(IDevice device, IData data, Crypto crypto) {
        this.device = device;
        this.data = data;
        this.crypto = crypto;
    }

    private void write(UUID uuid, byte[] data) {
        write(uuid, data, null);
    }

    private void write(UUID uuid, byte[] data, Consumer<byte[]> onComplete) {
        device.write(uuid, data, resp -> {
            System.out.println("write response: " + Util.bytesToHex(resp));
            if (onComplete != null) {
                onComplete.accept(resp);
            }
        });
    }

    protected void subscribeNotify(Consumer<Boolean> onTimeout) {
        System.out.println("Subscribe");
        final Disposable rxSub = device.onNotify(MiUUID.RX)
                .takeUntil(stopNotifyTrigger)
                //.timeout(3, TimeUnit.SECONDS, Observable.create(emitter -> {
                //    onTimeout.accept(true);
                //}))
                .subscribe(
                        this::receiveParcel
                );

        compositeDisposable.add(rxSub);
    }

    protected void init(Consumer<Boolean> callback, Consumer<Boolean> onTimeout) {
        System.out.println("init connection");
        device.prepare();
        System.out.println("init connect");
        device.connect(connect -> {
            subscribeNotify(onTimeout);

            callback.accept(connect);
        });
    }

    protected void receiveParcel(byte[] data) {
        if (data == null || data.length == 0) {
            System.out.println("received empty data");
        }
        System.out.println("recv message: " + Util.bytesToHex(data));
        if ((data[0] & 0xff) == 0x5a && (data[1] & 0xff) == 0xa5) {
            receiveBuffer = ByteBuffer.allocate(13 + (data[2] & 0xff));
            System.out.println("recv cappa: " + receiveBuffer.capacity());
            receiveBuffer.put(data);
        } else {
            receiveBuffer.put(data);
        }

        if (receiveBuffer.remaining() == 0) {
            byte[] message = new byte[receiveBuffer.position()];
            receiveBuffer.position(0);
            receiveBuffer.get(message);
            handleMessage(message);
        }
    }

    public AuthBase reset() {
        compositeDisposable.dispose();
        device.disconnect();
        data.clear();

        return this;
    }

    protected void handleMessage(byte[] message) {
    }

    public void exec() {
    }

    protected void writeChunked(byte[] cmd) {
        if (cmd == null) {
            return;
        }

        try {
            writePossible.acquire();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        ByteBuffer buf = ByteBuffer.wrap(crypto.encrypt(cmd));
        while (buf.remaining() > 0) {
            int len = Math.min(buf.remaining(), ChunkSize);
            byte[] chunk = new byte[len];
            buf.get(chunk, 0, len);

            write(MiUUID.TX, chunk);
        }

        writePossible.release();

        if (onWritten != null) {
            try {
                onWritten.accept(true);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
