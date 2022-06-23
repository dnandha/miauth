//
//  MiAuth - Authenticate and interact with Xiaomi devices over BLE
//  Copyright (C) 2022  Daljeet Nandha
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as
//  published by the Free Software Foundation, either version 3 of the
//  License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

        if (Arrays.equals(message, CommandLogin.Error)) {
            updateProgress("login: failed, missing id (9/9)");
            stopNotifyTrigger.onNext(true);
            try {
                onComplete.accept(false);
            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
        }

        if (!data.hasRemoteKey()) {
            updateProgress("login: handling remote key (3/9)");
            if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                writeParcel(MiUUID.AVDTP, data.getMyKey());
            } else if (Arrays.equals(message, CommandLogin.Received)) {
                updateProgress("login: app key sent (4/9)");
            } else if (Arrays.equals(message, CommandLogin.RespondKey)) {
                write(MiUUID.AVDTP, CommandLogin.ReceiveReady);
            } else {
                data.setRemoteKey(message);
                updateProgress("login: " + "remote key received (5/9)");
                write(MiUUID.AVDTP, CommandLogin.Received);
            }
        } else if (!data.hasRemoteInfo()) {
            updateProgress("login: handling remote info (6/9)");
            if (Arrays.equals(message, CommandLogin.RespondInfo)) {
                write(MiUUID.AVDTP, CommandLogin.ReceiveReady);
            } else {
                data.setRemoteInfo(message);
                updateProgress("login: remote info received -> calculate (7/9)");
                if (!data.calculate()) {
                    stopNotifyTrigger.onNext(true);
                    updateProgress("login: failed, invalid token (9/9)");
                    try {
                        onComplete.accept(false);
                    } catch (Exception e) {
                        System.err.println(e.getMessage());
                    }
                } else {
                    write(MiUUID.AVDTP, CommandLogin.Received, complete ->
                            write(MiUUID.AVDTP, CommandLogin.SendingCt));
                }
            }
        } else {
            if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                writeParcel(MiUUID.AVDTP, data.getCt());
            } else if (Arrays.equals(message, CommandLogin.Received)) {
                updateProgress("login: " + "ct sent (8/9)");
            } else if (Arrays.equals(message, CommandLogin.AuthConfirmed)) {
                stopNotifyTrigger.onNext(true);
                //compositeDisposable.dispose();

                updateProgress("login: succeeded (9/9)");
                try {
                    onComplete.accept(true);
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                }
            } else if (Arrays.equals(message, CommandLogin.AuthDenied)) {
                stopNotifyTrigger.onNext(true);
                //compositeDisposable.dispose();

                updateProgress("login: failed (9/9)");
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
            updateProgress("login: connecting (1/9)");
            init(onConnect -> {
                updateProgress("login: sending request (2/9)");
                write(MiUUID.UPNP, CommandLogin.Request);
                write(MiUUID.AVDTP, CommandLogin.SendingKey);
            }, onTimeout -> {
                //onComplete.accept(false);  // TODO
            });
        } else {
            updateProgress("login: subscribing (1/9)");
            subscribeNotify(timeout -> {
                //onComplete.accept(false);  // TODO
            });
            updateProgress("login: sending request (2/9)");
            write(MiUUID.UPNP, CommandLogin.Request);
            write(MiUUID.AVDTP, CommandLogin.SendingKey);
        }
    }
}
