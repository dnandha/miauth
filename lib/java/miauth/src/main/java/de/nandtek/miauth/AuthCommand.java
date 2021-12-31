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
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import io.reactivex.Observable;
import io.reactivex.ObservableSource;
import io.reactivex.Scheduler;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;
import io.reactivex.subjects.PublishSubject;

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
        System.out.println("command: handling message");

        byte[] response = null;
        if (receiveBuffer != null) {

            if (message == null) {
                message = new byte[receiveBuffer.position()];
                receiveBuffer.position(0);
                receiveBuffer.get(message);
            }

            byte[] dec = ((DataLogin) data).decryptUart(message);
            System.out.println("got message:" + Util.bytesToHex(dec));
            response = Arrays.copyOfRange(dec, 3, dec.length-4);
        }

        try {
            //stopNotifyTrigger.onNext(true);
            compositeDisposable.dispose();

            onResponse.accept(response);
        } catch (Exception e) {
            System.err.println("command: handle message error - " + e.getMessage());
        }
    }

    @Override
    public void exec() {
        final Disposable rxSub = device.onNotify(MiUUID.RX)
                .takeUntil(stopNotifyTrigger)
                .timeout(2, TimeUnit.SECONDS, Observable.create(emitter -> {
                    handleMessage(null);
                }))
                .subscribe(
                        this::receiveParcel,
                        throwable -> {
                            System.err.println("command error: " + throwable.getMessage());
                        }
                    );
        compositeDisposable.add(rxSub);

        System.out.println("Send command");
        writeChunked(command);
    }

    @Override
    protected void receiveParcel(byte[] data) {
        System.out.println("recv message: "+ Util.bytesToHex(data));
        if ((data[0] & 0xff) == 0x55 && (data[1] & 0xff) != 0xaa) {
            receiveBuffer = ByteBuffer.allocate(0x10 * (ChunkSize+2));
            receiveBuffer.put(data);
        } else {
            receiveBuffer.put(data);

            // TODO: this is not guaranteed to be true
            //if (data.length < ChunkSize+2) {
            //    byte[] message = new byte[receiveBuffer.position()];
            //    receiveBuffer.position(0);
            //    receiveBuffer.get(message);
            //    handleMessage(message);
            //}
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
