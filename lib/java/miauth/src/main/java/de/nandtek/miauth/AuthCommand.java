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

import io.reactivex.Scheduler;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;

public class AuthCommand extends AuthBase {
    private final byte[] command;

    // TODO: redesign
    public AuthCommand(IDevice device, DataLogin data, byte[] command) {
        super(device, data);
        this.command = command;
    }

    // TODO: extract interface
    public AuthBase setup(Scheduler scheduler, Consumer<byte[]> onResponse) {
        final Disposable receiveSub = receiveQueue
                .observeOn(scheduler)
                .timeout(2, TimeUnit.SECONDS)
                .subscribe(message -> {
                    byte[] dec = ((DataLogin)data).decryptUart(message);
                    onResponse.accept(Arrays.copyOfRange(dec, 3, dec.length-4));
                }, err -> onResponse.accept(null));
        compositeDisposable.add(receiveSub);

        return this;
    }

    @Override
    public void exec() {
        device.onNotify(MiUUID.RX, this::receiveParcel);

        writeChunked(command);
    }

    // TODO: generalize
    @Override
    protected void receiveParcel(byte[] data) {
        System.out.println("recv message: "+ Util.bytesToHex(data));
        if ((data[0] & 0xff) == 0x55 && (data[1] & 0xff) != 0xaa) {
            receiveBuffer = ByteBuffer.allocate(0x10 * (ChunkSize+2));
            receiveBuffer.put(data);
        } else {
            receiveBuffer.put(data);

            // TODO: this is not guaranteed to be true
            if (data.length < ChunkSize+2) {
                byte[] message = new byte[receiveBuffer.position()];
                receiveBuffer.position(0);
                receiveBuffer.get(message);
                receiveQueue.onNext(message);
            }
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
