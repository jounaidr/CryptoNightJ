public class ByteUtils {

    public static int savePutToBuffer(byte[] destination, byte[] source, int bufferPosition) {
        int currentPosition = bufferPosition;
        for (byte sourceByte : source) {
            if (currentPosition >= destination.length) {
                return currentPosition;
            }
            destination[currentPosition] = sourceByte;
            currentPosition++;
        }
        return currentPosition;
    }

    public static byte[] xor(byte[] in1, byte[] in2) {
        byte[] out = new byte[Math.min(in1.length, in2.length)];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((in1[i] ^ in2[i]) & 0xFF);
        }
        return out;
    }

    public static byte finiteMultiplication(byte v1, byte v2) {
        byte bTemps[] = new byte[8];
        byte bResult = 0;
        bTemps[0] = v1;
        for (int i = 1; i < bTemps.length; i++) {
            bTemps[i] = xtime(bTemps[i - 1]);
        }
        for (int i = 0; i < bTemps.length; i++) {
            if (getBit(v2, i) != 1) {
                bTemps[i] = 0;
            }
            bResult ^= bTemps[i];
        }
        return bResult;
    }

    private static byte getBit(byte value, int i) {
        final byte bMasks[] = {(byte) 0x01, (byte) 0x02, (byte) 0x04,
                (byte) 0x08, (byte) 0x10, (byte) 0x20,
                (byte) 0x40, (byte) 0x80};
        byte bBit = (byte) (value & bMasks[i]);
        return (byte) ((byte) (bBit >> i) & (byte) 0x01);
    }

    private static byte xtime(byte value) {
        int iResult = 0;
        iResult = (int) (value & 0x000000ff) * 02;
        return (byte) (((iResult & 0x100) != 0) ? iResult ^ 0x11b : iResult);
    }

    public static byte xor4Bytes(byte b1, byte b2, byte b3, byte b4) {
        byte bResult = 0;
        bResult ^= b1;
        bResult ^= b2;
        bResult ^= b3;
        bResult ^= b4;
        return bResult;
    }
}
