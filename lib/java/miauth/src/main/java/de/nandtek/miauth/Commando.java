package de.nandtek.miauth;

import io.reactivex.functions.Consumer;

public class Commando {
    private final byte[] cmd;
    private final Consumer<byte[]> onResponse;

    public Commando(byte[] cmd, Consumer<byte[]> onResponse) {
        this.cmd = cmd;
        this.onResponse = onResponse;
    }

    public byte[] getCommand() {
        return cmd;
    }

    public Consumer<byte[]> getOnResponse() {
        return onResponse;
    }

    public void respond(byte[] response) {
        try {
            onResponse.accept(response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
