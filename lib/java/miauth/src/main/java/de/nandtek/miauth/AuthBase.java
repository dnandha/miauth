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
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import io.reactivex.Observable;
import io.reactivex.disposables.CompositeDisposable;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;
import io.reactivex.subjects.PublishSubject;

public class AuthBase {
    public static int ChunkSize = 18;
    protected IDevice device;
    protected final IData data;
    protected ByteBuffer receiveBuffer;
    protected final CompositeDisposable compositeDisposable = new CompositeDisposable();
    protected final PublishSubject<Boolean> stopNotifyTrigger = PublishSubject.create();

    String progress;
    private Consumer<String> onProgressUpdate;

    public AuthBase(IDevice device, IData data) {
        this.device = device;
        this.data = data;
    }

    public void updateProgress(String p) {
        System.out.println(p);
        progress = p;

        if (onProgressUpdate != null) {
            try {
                onProgressUpdate.accept(progress);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void setProgressCallback(Consumer<String> onProgressUpdate) {
        this.onProgressUpdate = onProgressUpdate;
    }

    protected void write(UUID uuid, byte[] data) {
        write(uuid, data, null);
    }

    protected void write(UUID uuid, byte[] data, Consumer<byte[]> onComplete) {
        device.write(uuid, data, resp -> {
            System.out.println("auth: write response " + Util.bytesToHex(resp));
            if (onComplete != null) {
                onComplete.accept(resp);
            }
        });
    }

    protected void writeParcel(UUID uuid, byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        for (int i = 1; buf.remaining() > 0; i++) {
            int len = Math.min(buf.remaining(), ChunkSize);
            byte[] chunk = new byte[2 + len];
            chunk[0] = (byte) i;
            chunk[1] = (byte) 0;

            buf.get(chunk, 2, len);
            //final boolean isLast = buf.remaining() == 0;
            write(uuid, chunk);
        }
    }
    protected void subscribeNotify(Consumer<Boolean> onTimeout) {
        System.out.println("auth: subscribe");
        final Disposable upnpSub = device.onNotify(MiUUID.UPNP)
                .takeUntil(stopNotifyTrigger)
                .subscribe(
                    this::receiveParcel,
                        Throwable::printStackTrace
        );
        final Disposable avdtpSub = device.onNotify(MiUUID.AVDTP)
                .takeUntil(stopNotifyTrigger)
                .timeout(3, TimeUnit.SECONDS, Observable.create(emitter -> {
                    System.out.println("auth: subscription timeout");
                    stopNotifyTrigger.onNext(true);
                }))
                .subscribe(
                        this::receiveParcel,
                        Throwable::printStackTrace
                );

        final Disposable stopSub = stopNotifyTrigger.subscribe(
                next -> {
                    System.out.println("auth: subscription stopped");
                    onTimeout.accept(true);
                    //compositeDisposable.dispose();
        });

        compositeDisposable.add(upnpSub);
        compositeDisposable.add(avdtpSub);
        compositeDisposable.add(stopSub);
    }

    protected void init(Consumer<Boolean> callback, Consumer<Boolean> onTimeout) {
        device.prepare();
        device.connect(connect -> {
            subscribeNotify(onTimeout);

            callback.accept(connect);
        });
    }

    protected void receiveParcel(byte[] data) {
        System.out.println("auth: recv message " + Util.bytesToHex(data));
        int frame = data[0] & 0xff + 0x100 * data[1] & 0xff;
        System.out.println("auth: recv frame " + frame);
        if (frame == 0) {
            if (data.length == 6) {
                receiveBuffer = ByteBuffer.allocate((data[4] & 0xff + 0x100 * data[5] & 0xff) * ChunkSize);
            }
            handleMessage(data);
        } else if (frame > 0x10) {
            handleMessage(data);
        } else {
            receiveBuffer.put(data, 2, data.length - 2);
            if (receiveBuffer.remaining() < ChunkSize) {
                byte[] message = new byte[receiveBuffer.position()];
                receiveBuffer.position(0);
                receiveBuffer.get(message);
                handleMessage(message);
            }
        }
    }

    public void dispose() {
        compositeDisposable.dispose();
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
}
