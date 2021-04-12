import aes.AesKeyParam;
import aes.HashDirection;

import java.util.Arrays;

public class AesUtils {
    public static final int Nb = 4;

    private static final int[] FORWARD_S_BOX = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    //TODO: The following array, FORWARD_S_BOX_2D, is redundant and contains the same values as FORWARD_S_BOX
    //TODO: Refactor so that both AES key expansion and AES rounds methods use the same array...
    protected static final byte[][] FORWARD_S_BOX_2D = { {(byte) 0x63, (byte) 0x7c,
            (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f,
            (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b,
            (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76}, {(byte) 0xca,
            (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59,
            (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2,
            (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0},
            {(byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36,
                    (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5,
                    (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31,
                    (byte) 0x15}, {(byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3,
            (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07,
            (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27,
            (byte) 0xb2, (byte) 0x75}, {(byte) 0x09, (byte) 0x83, (byte) 0x2c,
            (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0,
            (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29,
            (byte) 0xe3, (byte) 0x2f, (byte) 0x84}, {(byte) 0x53, (byte) 0xd1,
            (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1,
            (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39,
            (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf}, {(byte) 0xd0,
            (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d,
            (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02,
            (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8},
            {(byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92,
                    (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6,
                    (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3,
                    (byte) 0xd2}, {(byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec,
            (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4,
            (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d,
            (byte) 0x19, (byte) 0x73}, {(byte) 0x60, (byte) 0x81, (byte) 0x4f,
            (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88,
            (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde,
            (byte) 0x5e, (byte) 0x0b, (byte) 0xdb}, {(byte) 0xe0, (byte) 0x32,
            (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24,
            (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62,
            (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79}, {(byte) 0xe7,
            (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5,
            (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4,
            (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08},
            {(byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c,
                    (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd,
                    (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b,
                    (byte) 0x8a}, {(byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66,
            (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61,
            (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1,
            (byte) 0x1d, (byte) 0x9e}, {(byte) 0xe1, (byte) 0xf8, (byte) 0x98,
            (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94,
            (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce,
            (byte) 0x55, (byte) 0x28, (byte) 0xdf}, {(byte) 0x8c, (byte) 0xa1,
            (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42,
            (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f,
            (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16}
    };

    private static final int[] INVERSE_S_BOX = {
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    private static final int[] RCON = {
            0x01, 0x02, 0x04, 0x08, 0x10,
            0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6,
            0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91
    };

    /**
     * Expand round keys
     *
     * @param inputKey     input key
     * @param roundsNumber number of AES rounds
     * @return 128 bits round keys as integer array int[roundNumber][4]
     */
    public static byte[] expandRoundKeys(byte[] inputKey, int roundsNumber) {
        AesKeyParam aesKeyParams = AesKeyParam.fromInputKey(inputKey);
        byte[] expandedKeys = new byte[roundsNumber * 16];
        System.arraycopy(inputKey, 0, expandedKeys, 0, inputKey.length);
        int iteration = 1;
        int bytesGenerated = aesKeyParams.getLengthBytes();
        while (bytesGenerated < expandedKeys.length) {
            generateNextBytes(expandedKeys, aesKeyParams, iteration);
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
     */
    private static void generateNextBytes(byte[] expandedKeys, AesKeyParam aesKeyParams, int iteration) {
        int bufferPosition = iteration * aesKeyParams.getLengthBytes();
        byte[] temporary = new byte[4];
        System.arraycopy(expandedKeys, bufferPosition - 4, temporary, 0, 4);
        temporary = scheduleCore(temporary, iteration);

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
            temporary = applySBox(temporary, HashDirection.ENCRYPT);
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
    private static byte[] getPreviousBlock(byte[] expandedKeys, int bufferPosition, AesKeyParam aesKeyParams) {
        byte[] previousBlock = new byte[4];
        System.arraycopy(expandedKeys, bufferPosition - aesKeyParams.getLengthBytes(), previousBlock, 0, 4);
        return previousBlock;
    }

    /**
     * Circular 8-bit rotate
     * @param input input byte array to rotate
     * @param shift number of bytes to rotate. Right rotation for positive value,
     *              left rotation direction for negative value
     * @return rotated byte array
     */
    public static byte[] circularByteRotate(byte[] input, int shift) {
        int trimmedShift = shift % input.length;
        byte[] output = new byte[input.length];
        for(int outputAddress = 0; outputAddress < input.length; outputAddress++) {
            int inputAddress = - trimmedShift + outputAddress;
            if(inputAddress >= input.length) {
                inputAddress = inputAddress - input.length;
            } else if(inputAddress < 0) {
                inputAddress = input.length + inputAddress;
            }
            output[outputAddress] = input[inputAddress];
        }
        return output;
    }

    /**
     * Implementation of rcon operation based on precalculated values
     * @param iteration iteration number
     * @return rcon value
     */
    public static byte rCon(int iteration) {
        if(iteration == 0) {
            return 0;
        }
        return (byte) RCON[iteration - 1];
    }

    /**
     * S-box operation
     * @param input byte array to map with s-box
     * @param direction HashDirection.ENCRYPT for encryption, HashDirection.DECRYPT for description
     * @return result of input byte array mapping with s-box
     */
    public static byte[] applySBox(byte[] input, HashDirection direction) {
        byte[] output = new byte[input.length];
        for(int i = 0; i < input.length; i++) {
            if(HashDirection.ENCRYPT.equals(direction)) {
                output[i] = (byte) FORWARD_S_BOX[(input[i] & 0xff)];
            } else if(HashDirection.DECRYPT.equals(direction)) {
                output[i] = (byte) INVERSE_S_BOX[(input[i] & 0xff)];
            }
        }
        return output;
    }

    /**
     * Core schedule routine to produce next 4 bytes of expanded keys
     * @param input previous 4 bytes of expanded keys
     * @param iteration number of iteration
     * @return next 4 bytes of expanded keys
     */
    public static byte[] scheduleCore(byte[] input, int iteration) {
        byte[] output = circularByteRotate(input, -1);
        output = applySBox(output, HashDirection.ENCRYPT);
        output[0] = (byte) ((output[0] ^ rCon(iteration)) & 0xFF);
        return output;
    }

    /**
     * Carry out subBytes, shiftRows, mixColumns on 16 byte input
     *
     * @param in  input bytes
     * @param key AES round key
     * @return Encrypted output
     */
    public static byte[] aesRound(byte[] in, byte[] key){
        byte[][] state = new byte[4][4];

        // Convert input into into 4x4 block in AES format
        for (int i = 0; i < state.length; i++){
            for (int j = 0; j < state[i].length; j++){
                byte[] portion = Arrays.copyOfRange(in, 4*i, 4*i+4);
                state[j][i] = portion[j];
            }
        }

        // Carry out AES methods
        state = subBytes(state);
        state = shiftRows(state);
        state = mixColumns(state);

        // Flatten block into 16 byte array
        byte[] out = new byte[16];
        for (int i = 0; i < state.length; i++){
            for (int j = 0; j < state[i].length; j++){
                out[4*i + j] = state[j][i];
            }
        }

        // XOR the output with the provided round key
        out = ByteUtils.xor(out, key);
        return out;
    }

    private static byte[][] subBytes(byte state[][]) {
        for (int i = 0; i < state.length; i++)
            for (int j = 0; j < state[i].length; j++)
                state[i][j] = sboxTransform(state[i][j]);
        return state;
    }

    private static byte sboxTransform(byte value) {
        byte bUpper = 0, bLower = 0;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return FORWARD_S_BOX_2D[bUpper][bLower];
    }

    private static byte[][] shiftRows(byte state[][]) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        // r=0 is not shifted
        stateNew[0] = state[0];
        for (int r = 1; r < state.length; r++)
            for (int c = 0; c < state[r].length; c++)
                stateNew[r][c] = state[r][(c + shift(r, Nb)) % Nb];

        return stateNew;
    }

    private static int shift(int r, int iNb) {
        return r;
    }

    private static byte[][] mixColumns(byte state[][]) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        for (int c = 0; c < Nb; c++) {
            stateNew[0][c] = ByteUtils.xor4Bytes(ByteUtils.finiteMultiplication(state[0][c], (byte) 0x02),
                    ByteUtils.finiteMultiplication(state[1][c], (byte) 0x03),
                    state[2][c], state[3][c]);
            stateNew[1][c] = ByteUtils.xor4Bytes(state[0][c],
                    ByteUtils.finiteMultiplication(state[1][c], (byte) 0x02),
                    ByteUtils.finiteMultiplication(state[2][c], (byte) 0x03),
                    state[3][c]);
            stateNew[2][c] = ByteUtils.xor4Bytes(state[0][c], state[1][c],
                    ByteUtils.finiteMultiplication(state[2][c], (byte) 0x02),
                    ByteUtils.finiteMultiplication(state[3][c], (byte) 0x03));
            stateNew[3][c] = ByteUtils.xor4Bytes(ByteUtils.finiteMultiplication(state[0][c], (byte) 0x03),
                    state[1][c], state[2][c],
                    ByteUtils.finiteMultiplication(state[3][c], (byte) 0x02));
        }
        return stateNew;
    }
}
