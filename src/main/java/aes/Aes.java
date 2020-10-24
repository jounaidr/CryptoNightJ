package aes;

public class Aes {

    /**
     * Expand round keys
     *
     * @param inputKey     input key
     * @param roundsNumber number of AES rounds
     * @param direction    encryption or decryption direction
     * @return 128 bits round keys as integer array int[roundNumber][4]
     */
    public byte[] expandRoundKeys(byte[] inputKey, int roundsNumber, HashDirection direction) {
        AesKeyParam aesKeyParams = AesKeyParam.fromInputKey(inputKey);
        byte[] expandedKeys = new byte[roundsNumber * 16];
        System.arraycopy(inputKey, 0, expandedKeys, 0, inputKey.length);
        int iteration = 1;
        int bytesGenerated = aesKeyParams.getLengthBytes();
        while (bytesGenerated < expandedKeys.length) {
            generateNextBytes(expandedKeys, aesKeyParams, iteration, direction);
            bytesGenerated += aesKeyParams.getLengthBytes();
            iteration++;
        }
        return expandedKeys;
    }

    /**
     * Produce next block of 16, 24 or 32-bytes for input key of 128, 192 or 256-bits length
     * @param expandedKeys byte array for expanded keys
     * @param aesKeyParams AES key parameters
     * @param iteration    number of iteration
     * @param direction    encryption or decryption direction
     */
    private void generateNextBytes(byte[] expandedKeys, AesKeyParam aesKeyParams, int iteration, HashDirection direction) {
        int bufferPosition = iteration * aesKeyParams.getLengthBytes();
        byte[] temporary = new byte[4];
        System.arraycopy(expandedKeys, bufferPosition - 4, temporary, 0, 4);
        temporary = AesUtils.scheduleCore(temporary, iteration);

        for (int i = 0; i < 4; i++) {
            byte[] previousBlock = getPreviousBlock(expandedKeys, bufferPosition, aesKeyParams);
            temporary = ByteUtils.xor(temporary, previousBlock);
            bufferPosition = ByteUtils.savePutToBuffer(expandedKeys, temporary, bufferPosition);
        }

        if (AesKeyParam.KEY_192_BITS.equals(aesKeyParams)) {
            for (int i = 0; i < 2; i++) {
                byte[] previousBlock = getPreviousBlock(expandedKeys, bufferPosition, aesKeyParams);
                temporary = ByteUtils.xor(temporary, previousBlock);
                bufferPosition = ByteUtils.savePutToBuffer(expandedKeys, temporary, bufferPosition);
            }
        }

        if (AesKeyParam.KEY_256_BITS.equals(aesKeyParams)) {
            temporary = AesUtils.applySBox(temporary, direction);
            for (int i = 0; i < 4; i++) {
                byte[] previousBlock = getPreviousBlock(expandedKeys, bufferPosition, aesKeyParams);
                temporary = ByteUtils.xor(temporary, previousBlock);
                bufferPosition = ByteUtils.savePutToBuffer(expandedKeys, temporary, bufferPosition);
            }
        }
    }

    /**
     * Get previous 4-bytes block with shift that is equals to input key length
     * @param expandedKeys expanded round keys
     * @param bufferPosition current position in expanded keys array
     * @param aesKeyParams AES input keys params
     * @return previous 4-bytes block shift that is equals to input key length
     */
    private byte[] getPreviousBlock(byte[] expandedKeys, int bufferPosition, AesKeyParam aesKeyParams) {
        byte[] previousBlock = new byte[4];
        System.arraycopy(expandedKeys, bufferPosition - aesKeyParams.getLengthBytes(), previousBlock, 0, 4);
        return previousBlock;
    }

}
