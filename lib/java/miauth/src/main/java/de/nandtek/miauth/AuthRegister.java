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
import java.util.concurrent.TimeUnit;

import io.reactivex.Scheduler;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;

public class AuthRegister extends AuthBase {
    public AuthRegister(IDevice device, DataRegister data) {
        super(device, data);
    }

    public AuthBase setup(Scheduler scheduler, Consumer<Boolean> onComplete) {
        System.out.println("Setting up register");

        final Disposable receiveSub = receiveQueue
                .observeOn(scheduler)
                .timeout(3, TimeUnit.SECONDS)
                .subscribe(message -> {
                    if (!data.hasRemoteInfo()) {
                        if (Arrays.equals(message, CommandRegister.SendingCt)) {
                            write(MiUUID.AVDTP, CommandLogin.ReceiveReady);
                        } else {
                            write(MiUUID.AVDTP, CommandLogin.Received, complete -> {
                                write(MiUUID.AVDTP, CommandRegister.SendingKey);
                            });
                            write(MiUUID.UPNP, CommandRegister.KeyExchange);

                            System.out.println("remote info received");
                            data.setRemoteInfo(message);
                        }
                    } else if (!data.hasRemoteKey()) {
                        if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                            writeParcel(MiUUID.AVDTP, data.getMyKey());
                        } else if (Arrays.equals(message, CommandLogin.Received)) {
                            System.out.println("register: " + "public key sent");
                        } else {
                            if (Arrays.equals(message, CommandRegister.SendingKey)) {
                                write(MiUUID.AVDTP, CommandLogin.ReceiveReady);
                            } else {
                                data.setRemoteKey(message);
                                System.out.println("register: " + "remote key received -> calculate");
                                data.calculate();
                                write(MiUUID.AVDTP, CommandLogin.Received);
                                write(MiUUID.AVDTP, CommandRegister.SendingCt);
                            }
                        }
                    } else {
                        if (Arrays.equals(message, CommandLogin.ReceiveReady)) {
                            writeParcel(MiUUID.AVDTP, data.getCt());
                        } else if (Arrays.equals(message, CommandLogin.Received)) {
                            write(MiUUID.UPNP, CommandRegister.AuthRequest);
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
                err -> {
                    data.clear();
                    device.disconnect();

                    System.err.println("register: " + err.getMessage());
                    onComplete.accept(false);
                }
        );
        compositeDisposable.add(receiveSub);

        return this;
    }

    @Override
    public void exec() {
        init(onConnect -> {
            write(MiUUID.UPNP, CommandRegister.GetInfo);
        });
    }
}
