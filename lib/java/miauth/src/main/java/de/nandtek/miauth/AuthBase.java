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

import java.nio.ByteBuffer;
import java.util.UUID;

import io.reactivex.disposables.CompositeDisposable;
import io.reactivex.functions.Consumer;
import io.reactivex.subjects.PublishSubject;

public abstract class AuthBase {
    public static int ChunkSize = 18;
    protected IDevice device;
    protected final IData data;
    protected final CompositeDisposable compositeDisposable = new CompositeDisposable();
    protected final PublishSubject<byte[]> receiveQueue = PublishSubject.create();
    protected ByteBuffer receiveBuffer;

    public AuthBase(IDevice device, IData data) {
        this.device = device;
        this.data = data;
    }

    protected void write(UUID uuid, byte[] data) {
        write(uuid, data, null);
    }

    protected void write(UUID uuid, byte[] data, Consumer<byte[]> onComplete) {
        device.write(uuid, data, resp -> {
            System.out.println("write response: " + Util.bytesToHex(resp));
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

    protected void init(Consumer<Boolean> callback) {
        device.prepare();
        device.connect(connect -> {
            device.onNotify(MiUUID.UPNP, this::receiveParcel);
            device.onNotify(MiUUID.AVDTP, this::receiveParcel);

            callback.accept(connect);
        });
    }

    protected void receiveParcel(byte[] data) {
        System.out.println("recv message: " + Util.bytesToHex(data));
        int frame = data[0] & 0xff + 0x100 * data[1] & 0xff;
        System.out.println("recv frame: " + frame);
        if (frame == 0) {
            if (data.length == 6) {
                receiveBuffer = ByteBuffer.allocate((data[4] & 0xff + 0x100 * data[5] & 0xff) * ChunkSize);
            }
            receiveQueue.onNext(data);
        } else if (frame > 0x10) {
            receiveQueue.onNext(data);
        } else {
            receiveBuffer.put(data, 2, data.length - 2);
            if (receiveBuffer.remaining() < ChunkSize) {
                byte[] message = new byte[receiveBuffer.position()];
                receiveBuffer.position(0);
                receiveBuffer.get(message);
                receiveQueue.onNext(message);
            }
        }
    }

    public void disconnect() {
        compositeDisposable.dispose();
        device.disconnect();
    }

    public abstract void exec();
}
