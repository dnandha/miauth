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

import java.util.Arrays;

import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;

public class AuthLogin extends AuthBase {
    private final Consumer<Boolean> onComplete;

    public AuthLogin(IDevice device, DataLogin data, Consumer<Boolean> onComplete) {
        super(device, data);

        this.onComplete = onComplete;

        setup();
    }

    @Override
    public void setup() {
        final Disposable receiveSub = receiveQueue
                //.observeOn(AndroidSchedulers.mainThread())
                .subscribe(message -> {
                    if (!data.hasRemoteKey()) {
                        if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                            writeParcel(Uuid.AVDTP, data.getMyKey());
                        } else if (Arrays.equals(message, CommandLogin.Received)) {
                            System.out.println("login: " + "app key sent");
                        } else if (Arrays.equals(message, CommandLogin.RespondKey)) {
                            write(Uuid.AVDTP, CommandLogin.ReceiveReady);
                        } else {
                            data.setRemoteKey(message);
                            System.out.println("login: " + "remote key received");
                            write(Uuid.AVDTP, CommandLogin.Received);
                        }
                    } else if (!data.hasRemoteInfo()) {
                        if (Arrays.equals(message, CommandLogin.RespondInfo)) {
                            write(Uuid.AVDTP, CommandLogin.ReceiveReady);
                        } else {
                            data.setRemoteInfo(message);
                            System.out.println("login: " + "remote info received -> calculate");
                            write(Uuid.AVDTP, CommandLogin.Received, complete -> {
                                write(Uuid.AVDTP, CommandLogin.SendingCt);
                            });
                            data.calculate();
                        }
                    } else {
                        if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                            writeParcel(Uuid.AVDTP, data.getCt());
                        } else if (Arrays.equals(message, CommandLogin.Received)) {
                            System.out.println("login: " + "ct sent");
                        } else if (Arrays.equals(message, CommandLogin.AuthConfirmed)) {
                            System.out.println("login: " + "login succeeded");
                            compositeDisposable.dispose(); // TODO: does this work?
                            onComplete.accept(true);
                        } else if (Arrays.equals(message, CommandLogin.AuthDenied)) {
                            System.err.println("login: " + "login failed");
                            compositeDisposable.dispose(); // TODO: does this work?
                            onComplete.accept(false);
                        }
                    }
                },
                err -> System.err.println("login: " + err.getMessage())
        );
        compositeDisposable.add(receiveSub);
    }

    @Override
    public void start() {
        init(onConnect -> {
            write(Uuid.UPNP, CommandLogin.Request);
            write(Uuid.AVDTP, CommandLogin.SendingKey);
        });
    }
}
