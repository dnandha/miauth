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

public class AuthRegister extends AuthBase {
    private final Consumer<Boolean> onComplete;
    private boolean button;

    public AuthRegister(IDevice device, DataRegister data, Consumer<Boolean> onComplete) {
        super(device, data);

        this.onComplete = onComplete;
        this.button = false;

        setup();
    }

    @Override
    public void setup() {
        final Disposable receiveSub = receiveQueue
                //.observeOn(AndroidSchedulers.mainThread())
                .subscribe(message -> {
                    if (!data.hasRemoteInfo()) {
                        if (Arrays.equals(message, CommandRegister.SendingCt)) {
                            write(Uuid.AVDTP, CommandLogin.ReceiveReady);
                        } else {
                            write(Uuid.AVDTP, CommandLogin.Received, complete -> {
                                write(Uuid.AVDTP, CommandRegister.SendingKey);
                            });
                            write(Uuid.UPNP, CommandRegister.KeyExchange);

                            if (!button) {
                                System.out.println("register: " + "Disconnect and restart auth!");
                                button = true;
                                onComplete.accept(false);
                            } else {
                                data.setRemoteInfo(message);
                            }
                        }
                    } else if (!data.hasRemoteKey()) {
                        if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                            writeParcel(Uuid.AVDTP, data.getMyKey());
                        } else if (Arrays.equals(message, CommandLogin.Received)) {
                            System.out.println("register: " + "public key sent");
                        } else {
                            if (Arrays.equals(message, CommandRegister.SendingKey)) {
                                write(Uuid.AVDTP, CommandLogin.ReceiveReady);
                            } else {
                                data.setRemoteKey(message);
                                System.out.println("register: " + "remote key received -> calculate");
                                data.calculate();
                                write(Uuid.AVDTP, CommandLogin.Received);
                                write(Uuid.AVDTP, CommandRegister.SendingCt);
                            }
                        }
                    } else {
                        if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                            writeParcel(Uuid.AVDTP, data.getCt());
                        } else if (Arrays.equals(message, CommandLogin.Received)) {
                            write(Uuid.UPNP, CommandRegister.AuthRequest);
                        } else if (Arrays.equals(message, CommandRegister.AuthConfirmed)) {
                            System.out.println("register: " + "registration succeeded");
                            compositeDisposable.dispose(); // TODO: does this work?
                            onComplete.accept(true);
                        } else if (Arrays.equals(message, CommandRegister.AuthDenied)) {
                            System.err.println("register: " + "registration failed");
                            compositeDisposable.dispose(); // TODO: does this work?
                            onComplete.accept(false);
                        }
                    }
                },
                err -> System.err.println("register: " + err.getMessage())
        );
        compositeDisposable.add(receiveSub);
    }

    @Override
    public void start() {
        init(onConnect -> {
            write(Uuid.UPNP, CommandRegister.GetInfo);
        });
    }
}
