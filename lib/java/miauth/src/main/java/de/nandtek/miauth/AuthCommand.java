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
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;

import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;

public class AuthCommand extends AuthBase {
    private final boolean encryption;

    private final Queue<Commando> cmdQueue;
    private final Queue<Commando> rcvQueue;

    public AuthCommand(IDevice device, IData data) {
        super(device, data);
        this.encryption = data != null;
        this.cmdQueue = new ArrayDeque<>();
        this.rcvQueue = new ArrayDeque<>();
    }

    @Override
    protected void handleMessage(byte[] message) {
        if (message == null) {
            return;
        }

        updateProgress("command: (2/2) handling message " + Util.bytesToHex(message));

        byte[] dec;  //  |x55|xAA| L | D | T | c |...|ck0|ck1|
        if (encryption) {
            dec = data.getParent().decryptUart(message);
            dec = Arrays.copyOfRange(dec, 0, dec.length - 4);
            System.out.println("command: decoded response:" + Util.bytesToHex(dec));
        } else {
            dec = Arrays.copyOfRange(message, 3, message.length - 2);
        }

        Commando cmd;
        while ((cmd = rcvQueue.poll()) != null) {
            if (((dec[1] == 1 || dec[1] == 2) && dec[2] == cmd.getCommand()[5])
                    || ((dec[1] != 1 && dec[1] != 2) && dec[1] == cmd.getCommand()[4])) {
                byte[] response = Arrays.copyOfRange(dec, 3, dec.length);
                cmd.respond(response);

                break;
            }
        }
    }

    @Override
    public void exec() {
        if (device.isConnected()) {
            final Disposable rxSub = device.onNotify(MiUUID.RX)
                    .takeUntil(stopNotifyTrigger)
                    .subscribe(
                            this::receiveParcel,
                            Throwable::printStackTrace
                    );
            compositeDisposable.add(rxSub);
        } else {
            // TODO
        }
    }

    public void clear() {
        cmdQueue.clear();
    }

    public void push(Commando cmd) {
        cmdQueue.add(cmd);
    }

    public void push(byte[] cmd, Consumer<byte[]> onResponse) {
        cmdQueue.add(new Commando(cmd, onResponse));
    }

    public boolean isEmpty() {
        return cmdQueue.isEmpty();
    }

    public void sendNext() {
        Commando cmd = cmdQueue.poll();
        if (rcvQueue.size() > 10) {
            rcvQueue.poll();
        }
        if (cmd != null) {
            writeChunked(cmd.getCommand());
            rcvQueue.add(cmd);
        }
    }

    public void handler() {
        byte[] message = null;
        if (receiveBuffer != null && !receiveBuffer.hasRemaining()) {
            message = new byte[receiveBuffer.position()];
            receiveBuffer.position(0);
            receiveBuffer.get(message);
            receiveBuffer.clear();
        }
        handleMessage(message);
    }

    @Override
    protected void receiveParcel(byte[] data) {
        if (data == null || data.length == 0) {
            System.out.println("command: recv empty data");
            return;
        }

        System.out.println("command: recv message "+ Util.bytesToHex(data));
        if ((data[0] & 0xff) == 0x55 && data.length > 2) {
            if ((data[1] & 0xff) != 0xaa) {
                receiveBuffer = ByteBuffer.allocate(0x10 + data[2]);
            } else {
                receiveBuffer = ByteBuffer.allocate(0x6 + data[2]);
            }
            receiveBuffer.put(data);
        } else if (receiveBuffer != null) {
            receiveBuffer.put(data);
        }

        //if (!waitTimeout && receiveBuffer != null && !receiveBuffer.hasRemaining()) {
        //    handler();
        //}
    }

    private void writeChunked(byte[] cmd) {
        updateProgress("command: (1/2) sending command " + Util.bytesToHex(cmd));

        byte[] msg = cmd;
        if (encryption) {
            msg = data.getParent().encryptUart(cmd);
        } else {
            byte[] crc = Util.crc(Arrays.copyOfRange(msg, 2, msg.length), 2);
            msg = Util.combineBytes(msg, crc);
        }
        ByteBuffer buf = ByteBuffer.wrap(msg);
        while (buf.remaining() > 0) {
            int len = Math.min(buf.remaining(), ChunkSize+2);
            byte[] chunk = new byte[len];
            buf.get(chunk, 0, len);

            write(MiUUID.TX, chunk);
        }
    }
}
