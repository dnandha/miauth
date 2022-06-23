package de.nandtek.miauth;

public class DataStump implements IData {
    private final Data parent;

    public DataStump(Data parent) {
        this.parent = parent;
    }

    @Override
    public boolean calculate() {
        return false;
    }

    @Override
    public boolean hasMyKey() {
        return false;
    }

    @Override
    public boolean hasRemoteInfo() {
        return false;
    }

    @Override
    public boolean hasRemoteKey() {
        return false;
    }

    @Override
    public void setRemoteInfo(byte[] data) {

    }

    @Override
    public void setRemoteKey(byte[] data) {

    }

    @Override
    public byte[] getRemoteKey() {
        return new byte[0];
    }

    @Override
    public byte[] getRemoteInfo() {
        return new byte[0];
    }

    @Override
    public byte[] getMyKey() {
        return new byte[0];
    }

    @Override
    public byte[] getCt() {
        return new byte[0];
    }

    @Override
    public Data getParent() {
        return parent;
    }

    @Override
    public void clear() {

    }
}
