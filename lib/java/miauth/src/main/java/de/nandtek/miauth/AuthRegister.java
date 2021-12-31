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
                stopNotifyTrigger.onNext(true);
                compositeDisposable.dispose();

                System.out.println("register: " + "registration succeeded");
                try {
                    onComplete.accept(true);
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                }
            } else if (Arrays.equals(message, CommandRegister.AuthDenied)) {
                stopNotifyTrigger.onNext(true);
                compositeDisposable.dispose();

                System.err.println("register: " + "registration failed");
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
            System.out.println("register: connecting");
            init(onConnect -> {
                write(MiUUID.UPNP, CommandRegister.GetInfo);
            }, timeout -> {
                onComplete.accept(false);
            });
        } else {
            subscribeNotify(timeout -> {
                onComplete.accept(false);
            });
            write(MiUUID.UPNP, CommandRegister.GetInfo);
        }
    }

    public AuthRegister clone() {
        return new AuthRegister(device, (DataRegister) data, onComplete);
    }

    public AuthLogin toLogin(DataLogin dataLogin, Consumer<Boolean> onComplete) {
        compositeDisposable.dispose();
        return new AuthLogin(device, dataLogin, onComplete);
    }
}
