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

public class AuthRegister extends AuthBase {

    private final Consumer<Boolean> onComplete;

    public AuthRegister(IDevice device, DataRegister data, Consumer<Boolean> onComplete) {
        super(device, data);
        this.onComplete = onComplete;
    }

    @Override
    protected void handleMessage(byte[] message) {
       System.out.println("register: handling message - " + Util.bytesToHex(message));

        if (!data.hasRemoteInfo()) {
            updateProgress("register: handling remote info (3/9)");
            if (Arrays.equals(message, CommandRegister.SendingCt)) {
                write(MiUUID.AVDTP, CommandLogin.ReceiveReady);
            } else {
                write(MiUUID.AVDTP, CommandLogin.Received, complete -> {
                    write(MiUUID.AVDTP, CommandRegister.SendingKey);
                });
                write(MiUUID.UPNP, CommandRegister.KeyExchange);

                updateProgress("register: remote info received (4/9)");
                data.setRemoteInfo(message);
            }
        } else if (!data.hasRemoteKey()) {
            updateProgress("register: handling remote key (5/9)");
            if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                writeParcel(MiUUID.AVDTP, data.getMyKey());
            } else if (Arrays.equals(message, CommandLogin.Received)) {
                updateProgress("register: " + "public key sent (6/9)");
            } else {
                if (Arrays.equals(message, CommandRegister.SendingKey)) {
                    write(MiUUID.AVDTP, CommandLogin.ReceiveReady);
                } else {
                    data.setRemoteKey(message);
                    updateProgress("register: " + "remote key received -> calculate (7/9)");
                    data.calculate();
                    write(MiUUID.AVDTP, CommandLogin.Received);
                    write(MiUUID.AVDTP, CommandRegister.SendingCt);
                    updateProgress("register: " + "ct sent (8/9)");
                }
            }
        } else {
            if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                writeParcel(MiUUID.AVDTP, data.getCt());
            } else if (Arrays.equals(message, CommandLogin.Received)) {
                write(MiUUID.UPNP, CommandRegister.AuthRequest);
            } else if (Arrays.equals(message, CommandRegister.AuthConfirmed)) {
                stopNotifyTrigger.onNext(true);
                //compositeDisposable.dispose();

                updateProgress("register: succeeded (9/9)");
                try {
                    onComplete.accept(true);
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                }
            } else if (Arrays.equals(message, CommandRegister.AuthDenied)) {
                stopNotifyTrigger.onNext(true);
                //compositeDisposable.dispose();

                updateProgress("register: failed (9/9)");
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
        super.exec();

        // TODO: improve this
        if (!device.isConnected()) {
            updateProgress("register: connecting (1/9)");
            init(onConnect -> {
                updateProgress("register: sending request (2/9)");
                write(MiUUID.UPNP, CommandRegister.GetInfo);
            }, timeout -> {
                onComplete.accept(false);
            });
        } else {
            updateProgress("register: subscribing (1/9)");
            subscribeNotify(timeout -> {
                onComplete.accept(false);
            });
            updateProgress("register: sending request (2/9)");
            write(MiUUID.UPNP, CommandRegister.GetInfo);
        }
    }

    public AuthRegister freshClone() {
        return new AuthRegister(device, new DataRegister(data.getParent()), onComplete);
    }

    public AuthLogin toLogin(DataLogin dataLogin, Consumer<Boolean> onComplete) {
        dispose();
        return new AuthLogin(device, dataLogin, onComplete);
    }
}
