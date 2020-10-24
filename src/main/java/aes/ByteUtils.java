package aes;

public class ByteUtils {

    private ByteUtils() {
    }

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

    public static byte[] xor(byte[] input1, byte[] input2) {
        byte[] output = new byte[4];
        for (int i = 0; i < 4; i++) {
            output[i] = (byte) ((input1[i] ^ input2[i]) & 0xFF);
        }
        return output;
    }
}
