public class Cryptonight {
    private byte[] out;

    public Cryptonight(String inputData) {
        byte[] keccakInput = keccak(inputData);
        byte[] scratchPad = new byte[2097152];

        //Make key
        byte[] key = new byte[32];
        System.arraycopy(keccakInput, 0, key, 0, 32);

        //Make blocks
        byte[][] blocks = new byte[8][];
        for (int i = 0; i < 8; ++i)
            System.arraycopy(keccakInput, 64 + 16 * i, blocks[i], 0, 16);

        byte[][] keys = new byte[11][];
        keys[0]=key;
        for (int i = 0; i < 10; ++i) {
            keys[i+1]=new byte[32];
            Rijndael.expandKey(keys[i], keys[i+1], 0, 32, 32);
        }

        //byte[] pad = new byte[2097152];

        //Encrypt blocks
        for (int bid = 0; bid < 8; ++bid) {
            for (int i = 0; i < 10; ++i) {
                blocks[bid] = AES.encrypt(blocks[i], keys[i+1]);
            }
        }

//        return Utils.byteToHex(out);
    }

    public byte[] returnHash(){
        return null;
    }

    /**
     * Expand round keys
     *
     * @param inputKey     input key
     * @param roundsNumber number of AES rounds
     * @param direction    encryption or decryption direction
     * @return 128 bits round keys as integer array int[roundNumber][4]
     */
    private byte[] expandRoundKeys(byte[] inputKey, int roundsNumber, @NotNull HashDirection direction) {
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

    private byte[] keccak(String data){
        Keccak1600 keccakHasher = new Keccak1600(data);
        byte[] out = keccakHasher.digestArray();
        return out;
    }
}
