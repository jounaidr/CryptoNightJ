package aes;

public enum AesKeyParam {

    KEY_128_BITS(16, 11), KEY_192_BITS(24, 13), KEY_256_BITS(32, 15);

    private final int lengthBytes;
    private final int standardRoundNumber;

    AesKeyParam(int lengthBytes, int standardRoundNumber) {
        this.lengthBytes = lengthBytes;
        this.standardRoundNumber = standardRoundNumber;
    }

    public static AesKeyParam fromInputKey(byte[] inputKey) {
        for(AesKeyParam key : values()) {
            if(key.lengthBytes == inputKey.length) {
                return key;
            }
        }
        throw new IllegalArgumentException("Please provide valid length input key: 128, 192 or 256-bits");
    }

    public int getLengthBytes() {
        return lengthBytes;
    }

    public int getStandardRoundNumber() {
        return standardRoundNumber;
    }
}
