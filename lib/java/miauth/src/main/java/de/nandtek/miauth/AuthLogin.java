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

import java.util.Arrays;

import io.reactivex.functions.Consumer;

public class AuthLogin extends AuthBase {
    private final Consumer<Boolean> onComplete;

    public AuthLogin(IDevice device, DataLogin data, Consumer<Boolean> onComplete) {
        super(device, data);
        this.onComplete = onComplete;
    }

    @Override
    protected void handleMessage(byte[] message) {
        System.out.println("login: handling message");
        if (!data.hasRemoteKey()) {
            System.out.println("login: handling remote key");
            if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                writeParcel(MiUUID.AVDTP, data.getMyKey());
            } else if (Arrays.equals(message, CommandLogin.Received)) {
                System.out.println("login: " + "app key sent");
            } else if (Arrays.equals(message, CommandLogin.RespondKey)) {
                write(MiUUID.AVDTP, CommandLogin.ReceiveReady);
            } else {
                data.setRemoteKey(message);
                System.out.println("login: " + "remote key received");
                write(MiUUID.AVDTP, CommandLogin.Received);
            }
        } else if (!data.hasRemoteInfo()) {
            System.out.println("login: handling remote info");
            if (Arrays.equals(message, CommandLogin.RespondInfo)) {
                write(MiUUID.AVDTP, CommandLogin.ReceiveReady);
            } else {
                data.setRemoteInfo(message);
                System.out.println("login: " + "remote info received -> calculate");
                if (!data.calculate()) {
                    stopNotifyTrigger.onNext(true);
                    System.out.println("login: " + "failed, invalid token");
                    try {
                        onComplete.accept(false);
                    } catch (Exception e) {
                        System.err.println(e.getMessage());
                    }
                } else {
                    write(MiUUID.AVDTP, CommandLogin.Received, complete -> {
                        write(MiUUID.AVDTP, CommandLogin.SendingCt);
                    });
                }
            }
        } else {
            if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                writeParcel(MiUUID.AVDTP, data.getCt());
            } else if (Arrays.equals(message, CommandLogin.Received)) {
                System.out.println("login: " + "ct sent");
            } else if (Arrays.equals(message, CommandLogin.AuthConfirmed)) {
                stopNotifyTrigger.onNext(true);
                //compositeDisposable.dispose();

                System.out.println("login: " + "succeeded");
                try {
                    onComplete.accept(true);
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                }
            } else if (Arrays.equals(message, CommandLogin.AuthDenied)) {
                stopNotifyTrigger.onNext(true);
                //compositeDisposable.dispose();

                System.err.println("login: " + "failed");
                try {
                    onComplete.accept(false);
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
                System.out.println("login: sending request");
                write(MiUUID.UPNP, CommandLogin.Request);
                write(MiUUID.AVDTP, CommandLogin.SendingKey);
            }, onTimeout -> {
                //onComplete.accept(false);
            });
        } else {
            System.out.println("login: subscribing");
            subscribeNotify(timeout -> {
                //onComplete.accept(false);
            });
            System.out.println("login: sending request");
            write(MiUUID.UPNP, CommandLogin.Request);
            write(MiUUID.AVDTP, CommandLogin.SendingKey);
        }
    }

    public AuthCommand toCommand(byte[] command, Consumer<byte[]> onResponse) {
        dispose();
        if (!(data instanceof DataLogin)) {
            System.err.println("login: can't create command, no login data");
            return null;
        }
        return new AuthCommand(device, (DataLogin) data, command, onResponse);
    }
}
