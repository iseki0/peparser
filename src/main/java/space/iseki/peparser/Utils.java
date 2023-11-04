package space.iseki.peparser;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;



final class IntReader {
    private static final VarHandle INT_LE_AH = MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);
    private static final VarHandle SHORT_LE_AH = MethodHandles.byteArrayViewVarHandle(short[].class, ByteOrder.LITTLE_ENDIAN);
    private static final VarHandle LONG_LE_AH = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);


    byte[] data;
    int off;

    IntReader(byte[] data, int off) {
        this.data = data;
        this.off = off;
    }

    int readInt() {
        var i = (int) INT_LE_AH.get(data, off);
        off += 4;
        return i;
    }

    short readShort() {
        var i = (short) SHORT_LE_AH.get(data, off);
        off += 2;
        return i;
    }

    int readByte() {
        return data[off++] & 0xff;
    }

    long readLong() {
        var i = (long) LONG_LE_AH.get(data, off);
        off += 8;
        return i;
    }
}
