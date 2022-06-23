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
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import de.nandtek.miauth.DataLogin;
import de.nandtek.miauth.IDevice;
import de.nandtek.miauth.MiUUID;
import de.nandtek.miauth.Util;
import io.reactivex.Observable;
import io.reactivex.functions.Consumer;
import io.reactivex.internal.schedulers.ScheduledDirectPeriodicTask;

public class AuthLogin extends AuthBase {
    private Consumer<byte[]> onResponse;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private byte[] sendMessage = null;
    private byte lastCommandLength = 0;
    private final ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor();

    public AuthLogin(IDevice device, DataLogin data, Crypto crypto, Consumer<byte[]> onResponse) {
        super(device, data, crypto);
        this.onResponse = onResponse;
    }

    public void sendCommand(byte[] command, Consumer<byte[]> onResponse) {
        //this.sendMessage = command;
        this.sendBuffer = ByteBuffer.wrap(command);
        this.onResponse = onResponse;
    }

    public void sendCommandNoHandle(byte[] command, Consumer<Boolean> onWritten) {
        this.sendBuffer = ByteBuffer.wrap(command);
        this.onWritten = onWritten;
        this.onResponse = null;
    }

    @Override
    protected void handleMessage(byte[] msg) {
        byte[] message = crypto.decrypt(msg);
        byte[] cmd = Arrays.copyOf(message, 7);
        byte[] payload = Arrays.copyOfRange(message, 7, message.length);

        System.out.println("login: handling message " + Util.bytesToHex(message));
        if (Arrays.equals(cmd, CommandLogin.AckInit)) {
            System.out.println("login: got init " + Util.bytesToHex(message));
            data.setRemoteKey(Arrays.copyOf(payload, 16));
            data.setRemoteInfo(Arrays.copyOfRange(payload, 16, payload.length));

            crypto.setBleData(data.getRemoteKey());

            sendMessage = CommandLogin.CmdPing(data.getParent().getToken());
        } else if (Arrays.equals(cmd, CommandLogin.AckPing)) {
            System.out.println("login: got ping");

            crypto.setAppData(data.getParent().getToken());

            sendMessage = CommandLogin.CmdPair(data.getRemoteInfo());
        } else if (Arrays.equals(cmd, CommandLogin.AckPre)) {
            System.out.println("login: got pre");

            try {
                onResponse.accept(new byte[0]);
            } catch (Exception e) {
                e.printStackTrace();
            }
            // Will time out -> Press Power
            // Meanwhile send either pair or ping command
            sendMessage = CommandLogin.CmdPair(data.getRemoteInfo());
        } else if (Arrays.equals(cmd, CommandLogin.AckPair)) {
            System.out.println("login: " + "login succeeded");
            try {
                onResponse.accept(new byte[1]);
            } catch (Exception e) {
                e.printStackTrace();
            }

            //sendMessage = command;
            sendMessage = null;
        } else if (cmd[2] == lastCommandLength){
        //} else {
            //sendMessage = null;
            System.out.println("login: " + "command succeeded");

            //stopNotifyTrigger.onNext(true);
            //compositeDisposable.dispose();

            if (this.onResponse != null) {
                try {
                    onResponse.accept(Arrays.copyOfRange(message, 7, message.length));
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                }
            }
        }
    }

    @Override
    public void exec() {
        // TODO: improve this
        if (!device.isConnected()) {
            System.out.println("login: connecting");
            init(onConnect -> {
                System.out.println("login: connected");
                device.read(MiUUID.NAME,response -> {
                    crypto.setName(response);
                    System.out.println("login: got name " + new String(response));

                    sendMessage = CommandLogin.CmdInit;

                    ScheduledDirectPeriodicTask task = new ScheduledDirectPeriodicTask(() -> {
                        if (sendBuffer != null && sendBuffer.hasRemaining()) {
                            System.out.println("login: send buffer");
                            final byte[] msg = new byte[sendBuffer.capacity()];
                            sendBuffer.position(0);
                            sendBuffer.get(msg);
                            lastCommandLength = msg[msg.length-1];
                            writeChunked(msg);
                        } else if (sendMessage != null) {
                            System.out.println("login: send message");
                            //lastCommandLength = sendMessage[sendMessage.length-1];
                            writeChunked(sendMessage);
                        }
                    });
                    ScheduledFuture<?> f = exec.scheduleAtFixedRate(task, 0, 1, TimeUnit.SECONDS);
                    task.setFuture(f);
                    compositeDisposable.add(task);
                });
            }, onTimeout -> {
                // -> repeat message or press Power
                // this is not happening
                onResponse.accept(null);
            });
        } else {
        }
    }
}
