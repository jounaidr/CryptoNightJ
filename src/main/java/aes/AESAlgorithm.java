/*
 * Copyright 2007 Richard Chen
 * mail: richardchen0310@gmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package aes;

import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.io.UnsupportedEncodingException;

/**
 * <p>Title: The Cipher Library</p>
 * <p>Description: The AESAlgorithm is designed for encrypting and decripting using AES Algorithm </p>
 * <p>Example: </p>
 * <pre>
 * AESAlgorithm alg = new AESAlgorithm(AESAlgorithm.KEY_SIZE_128); // up to 4096
 * byte[] bytesKey = alg.createKey();
 * int[] wordsKeyExpansion = alg.createKeyExpansion(bytesKey);
 * String strMessage = "this is a test
 * byte[] bytesMessage = strMessage.getBytes();
 * byte[] bytesEncrypted = alg.cipher(bytesMessage, wordsKeyExpansion);
 * byte[] bytesDecrypted = alg.invCipher(bytesEncrypted, wordsKeyExpansion);
 *</pre>
 *
 * <p>Date: 2001</p>
 * @author Richard
 * @version 1.0
 */
public class AESAlgorithm {
    public static final int KEY_SIZE_128 = 128;
    public static final int KEY_SIZE_192 = 192;
    public static final int KEY_SIZE_256 = 256;
    public static final int KEY_SIZE_512 = 512;
    public static final int KEY_SIZE_1024 = 1024;
    public static final int KEY_SIZE_2048 = 2048;
    public static final int KEY_SIZE_4096 = 4096;
    public static final int NB_VALUE = 4;

    private static String DEFAULT_CHARSET = "UTF-8";

    private static int m_version = 1;

    /**
     * check if the key size is valid
     * @param keySize int
     * @return boolean
     */
    public static boolean isValidKeySize(int keySize) {
        if (keySize == AESAlgorithm.KEY_SIZE_128 ||
                keySize == AESAlgorithm.KEY_SIZE_192 ||
                keySize == AESAlgorithm.KEY_SIZE_256 ||
                keySize == AESAlgorithm.KEY_SIZE_512 ||
                keySize == AESAlgorithm.KEY_SIZE_1024 ||
                keySize == AESAlgorithm.KEY_SIZE_2048 ||
                keySize == AESAlgorithm.KEY_SIZE_4096) {
            return true;
        } else {
            return false;
        }

    }

    // AES-128 Nk=4, Nb=4, Nr=10
    // AES-192 Nk=6, Nb=4, Nr=12
    // AES-256 Nk=8, Nb=4, Nr=14
    protected int Nk = 4;
    protected int Nb = NB_VALUE;
    protected int Nr = 10;
    public int getNk() {
        return Nk;
    }

    public int getNb() {
        return Nb;
    }

    public int getNr() {
        return Nr;
    }

    //public String strTrace = new String();

    protected static final byte[][] sbox = { {(byte) 0x63, (byte) 0x7c,
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
    protected static final byte[][] sboxInv = { {(byte) 0x52, (byte) 0x09,
            (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5,
            (byte) 0x38, (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e,
            (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb}, {(byte) 0x7c,
            (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f,
            (byte) 0xff, (byte) 0x87, (byte) 0x34, (byte) 0x8e, (byte) 0x43,
            (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb},
            {(byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6,
                    (byte) 0xc2, (byte) 0x23, (byte) 0x3d, (byte) 0xee, (byte) 0x4c,
                    (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3,
                    (byte) 0x4e}, {(byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66,
            (byte) 0x28, (byte) 0xd9, (byte) 0x24, (byte) 0xb2, (byte) 0x76,
            (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b,
            (byte) 0xd1, (byte) 0x25}, {(byte) 0x72, (byte) 0xf8, (byte) 0xf6,
            (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16,
            (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d,
            (byte) 0x65, (byte) 0xb6, (byte) 0x92}, {(byte) 0x6c, (byte) 0x70,
            (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9,
            (byte) 0xda, (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57,
            (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84}, {(byte) 0x90,
            (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc,
            (byte) 0xd3, (byte) 0x0a, (byte) 0xf7, (byte) 0xe4, (byte) 0x58,
            (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06},
            {(byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca,
                    (byte) 0x3f, (byte) 0x0f, (byte) 0x02, (byte) 0xc1, (byte) 0xaf,
                    (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a,
                    (byte) 0x6b}, {(byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41,
            (byte) 0x4f, (byte) 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97,
            (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4,
            (byte) 0xe6, (byte) 0x73}, {(byte) 0x96, (byte) 0xac, (byte) 0x74,
            (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85,
            (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c,
            (byte) 0x75, (byte) 0xdf, (byte) 0x6e}, {(byte) 0x47, (byte) 0xf1,
            (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5,
            (byte) 0x89, (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e,
            (byte) 0xaa, (byte) 0x18, (byte) 0xbe, (byte) 0x1b}, {(byte) 0xfc,
            (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2,
            (byte) 0x79, (byte) 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0,
            (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4},
            {(byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88,
                    (byte) 0x07, (byte) 0xc7, (byte) 0x31, (byte) 0xb1, (byte) 0x12,
                    (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec,
                    (byte) 0x5f}, {(byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9,
            (byte) 0x19, (byte) 0xb5, (byte) 0x4a, (byte) 0x0d, (byte) 0x2d,
            (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9,
            (byte) 0x9c, (byte) 0xef}, {(byte) 0xa0, (byte) 0xe0, (byte) 0x3b,
            (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0,
            (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83,
            (byte) 0x53, (byte) 0x99, (byte) 0x61}, {(byte) 0x17, (byte) 0x2b,
            (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6,
            (byte) 0x26, (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63,
            (byte) 0x55, (byte) 0x21, (byte) 0x0c, (byte) 0x7d}
    };
    protected static final int Rcon[] = {0x01000000,
            0x01000000, 0x02000000, 0x04000000,
            0x08000000,
            0x10000000, 0x20000000, 0x40000000,
            0x80000000,
            0x1b000000, 0x36000000, 0x6c000000};

    public AESAlgorithm() {
    }

    public AESAlgorithm(int iBlockLength) {
        switch (iBlockLength) {
            case KEY_SIZE_128:
                Nk = 4;
                Nb = 4;
                Nr = 10;
                break;
            case KEY_SIZE_192:
                Nk = 6;
                Nb = 4;
                Nr = 12;
                break;
            case KEY_SIZE_256:
                Nk = 8;
                Nb = 4;
                Nr = 14;
                break;
            case KEY_SIZE_512:
                Nk = 16;
                Nb = 4;
                Nr = 22;
                break;
            case KEY_SIZE_1024:
                Nk = 32;
                Nb = 4;
                Nr = 38;
                break;
            case KEY_SIZE_2048:
                Nk = 64;
                Nb = 4;
                Nr = 70;
                break;
            case KEY_SIZE_4096:
                Nk = 128;
                Nb = 4;
                Nr = 134;
                break;
            default:
                throw new java.lang.UnsupportedOperationException(
                        "key length can only be:128, 192 or 256");
        }
    }

    // get ith bit of value, 0 <= i <= 7
    // for value = B7B6B5B4B3B2B1B0
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

    private static byte finiteMultiplication(int v1, int v2) {
        return finiteMultiplication((byte) v1, (byte) v2);
    }

    private static byte finiteMultiplication(byte v1, byte v2) {
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

    /**
     * encrypt the input message (bytesMessage)
     * the procedure is change the message in the packet format listed below, and then use aes to encrypt
     * |message size|version of richard AES|message body|
     * 0------------7---------------------11-------------
     * we need to record message size becord aes is a block cipher algorithm,
     * if you don't remember the original message size, you might get lot of 0x00 at your decrypted message.
     * @param bytesMessage byte[] message which will be encrypted
     * @param wordsKeyExpansion int[] key expansion array (generated by key byte array)
     * @return byte[] the encrypted bytes array
     */
    public byte[] cipher(byte bytesMessage[], int wordsKeyExpansion[]) {
        // create packet
        long lMessageSize = bytesMessage.length;
        byte[] bytesPacket = new byte[bytesMessage.length+12];
        bytesPacket[0] = (byte) (0xFFl & lMessageSize);
        bytesPacket[1] = (byte) ((0xFF00l & lMessageSize) >> 8);
        bytesPacket[2] = (byte) ((0xFF0000l & lMessageSize) >> 16);
        bytesPacket[3] = (byte) ((0xFF000000l & lMessageSize) >> 24);
        bytesPacket[4] = (byte) ((0xFF00000000l & lMessageSize) >> 32);
        bytesPacket[5] = (byte) ((0xFF0000000000l & lMessageSize) >> 40);
        bytesPacket[6] = (byte) ((0xFF000000000000l & lMessageSize) >> 48);
        bytesPacket[7] = (byte) ((0xFF00000000000000l & lMessageSize) >> 56);

        bytesPacket[8]  = (byte) (0xFF & m_version);
        bytesPacket[9]  = (byte) ((0x00FF & m_version) >> 8);
        bytesPacket[10] = (byte) ((0x0000FF & m_version) >> 16);
        bytesPacket[11] = (byte) ((0x000000FF & m_version) >> 24);

        // copy message to packet
        for(int i = 0; i < bytesMessage.length; i++) {
            bytesPacket[i+12] = bytesMessage[i];
        }

        AESBlocks abk = new AESBlocks(bytesPacket);
        AESBlocks abkEncrypted = new AESBlocks(abk.getDataLength());

        byte out[][];
        for (int i = 0; i < abk.size(); i++) {
            out = this.cipher(abk.getBlock(i), wordsKeyExpansion);
            abkEncrypted.addBlock(out);
        }

        return abkEncrypted.getBytes();
    }


    /**
     * encrypt the input message (bytesMessage)
     * @param bytesMessage byte[][] message which will be encrypted
     * @param wordsKeyExpansion int[] key expansion array (generated by key byte array)
     * @return byte[][]
     */
    private byte[][] cipher(byte bytesMessage[][], int wordsKeyExpansion[]) {
        byte state[][] = new byte[4][Nb];
        state = bytesMessage;
        //strTrace = "";

        //strTrace += AESMessage.getTrace("Cipher Started Initial state", state); // debug trace
        state = addRoundKey(state, wordsKeyExpansion, 0);
        //strTrace += AESMessage.getTrace("After addRoundKey", state); // debug trace

        for (int round = 1; round <= Nr - 1; round++) {
            //strTrace += AESMessage.getTrace("Round " + round + "Started"); // debug trace
            state = subBytes(state);
            //strTrace += AESMessage.getTrace("After subBytes", state); // debug trace
            state = shiftRows(state);
            //strTrace += AESMessage.getTrace("After shiftRows", state); // debug trace
            state = mixColumns(state);
            //strTrace += AESMessage.getTrace("After mixColumns", state); // debug trace
            state = addRoundKey(state, wordsKeyExpansion, round * Nb);
            //strTrace += AESMessage.getTrace("After addRoundKey", state); // debug trace
        }
        //strTrace += AESMessage.getTrace("Final round Started"); // debug trace
        state = subBytes(state);
        //strTrace += AESMessage.getTrace("After subBytes", state); // debug trace
        state = shiftRows(state);
        //strTrace += AESMessage.getTrace("After shiftRows", state); // debug trace
        state = addRoundKey(state, wordsKeyExpansion, Nr * Nb);
        //strTrace += AESMessage.getTrace("After addRoundKey", state); // debug trace
        return state;
    }

    public byte[] aesRound(byte[] in, byte[] key){
        byte[][] state = new byte[4][4];

        for (int i = 0; i < state.length; i++){
            for (int j = 0; j < state[i].length; j++){
                byte[] portion = Arrays.copyOfRange(in, 4*i, 4*i+4);
                state[j][i] = portion[j];
            }
        }

        state = subBytes(state);

        state = shiftRows(state);

        state = mixColumns(state);

        byte[] out = new byte[16];

        for (int i = 0; i < state.length; i++){
            for (int j = 0; j < state[i].length; j++){
                out[4*i + j] = state[j][i];
            }
        }

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
        return sbox[bUpper][bLower];
    }

    private byte[][] shiftRows(byte state[][]) {
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

    private byte[][] mixColumns(byte state[][]) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        for (int c = 0; c < Nb; c++) {
            stateNew[0][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x02),
                    finiteMultiplication(state[1][c], 0x03),
                    state[2][c], state[3][c]);
            stateNew[1][c] = xor4Bytes(state[0][c],
                    finiteMultiplication(state[1][c], 0x02),
                    finiteMultiplication(state[2][c], 0x03),
                    state[3][c]);
            stateNew[2][c] = xor4Bytes(state[0][c], state[1][c],
                    finiteMultiplication(state[2][c], 0x02),
                    finiteMultiplication(state[3][c], 0x03));
            stateNew[3][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x03),
                    state[1][c], state[2][c],
                    finiteMultiplication(state[3][c], 0x02));
        }
        return stateNew;
    }

    private byte xor4Bytes(byte b1, byte b2, byte b3, byte b4) {
        byte bResult = 0;
        bResult ^= b1;
        bResult ^= b2;
        bResult ^= b3;
        bResult ^= b4;
        return bResult;
    }

    private byte[][] addRoundKey(byte state[][], int w[], int l) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        for (int c = 0; c < Nb; c++) {
            stateNew[0][c] = (byte) (state[0][c] ^ getByte(w[l + c], 3));
            stateNew[1][c] = (byte) (state[1][c] ^ getByte(w[l + c], 2));
            stateNew[2][c] = (byte) (state[2][c] ^ getByte(w[l + c], 1));
            stateNew[3][c] = (byte) (state[3][c] ^ getByte(w[l + c], 0));
        }
        return stateNew;
    }

    // iByte is the byte number of value
    // value = |byte3|byte2|byte1|byte0|
    private byte getByte(int value, int iByte) {
        return (byte) ((value >>> (iByte * 8)) & 0x000000ff);
    }

    private static int subWord(int word) {
        int newWord = 0;
        newWord ^= (int) sboxTransform((byte) (word >>> 24)) & 0x000000ff;
        newWord <<= 8;

        newWord ^= (int) sboxTransform((byte) ((word & 0xff0000) >>> 16)) &
                0x000000ff;
        newWord <<= 8;

        newWord ^= (int) sboxTransform((byte) ((word & 0xff00) >>> 8)) &
                0x000000ff;
        newWord <<= 8;

        newWord ^= (int) sboxTransform((byte) (word & 0xff)) & 0x000000ff;

        return newWord;
    }

    private static int rotWord(int word) {
        return (word << 8) ^ ((word >> 24) & 0x000000ff);
    }

    private static int toWord(byte b1, byte b2, byte b3, byte b4) {
        int word = 0;
        word ^= ((int) b1) << 24;

        word ^= (((int) b2) & 0x000000ff) << 16;

        word ^= (((int) b3) & 0x000000ff) << 8;

        word ^= (((int) b4) & 0x000000ff);
        return word;
    }

    public void keyExpansion(byte key[], int w[]) {
        int iTemp = 0;
        int i = 0;

        while (i < Nk) {
            w[i] = toWord(key[4 * i], key[4 * i + 1], key[4 * i + 2],
                    key[4 * i + 3]);
            i++;
        }

        i = Nk;

        while (i < Nb * (Nr + 1)) {
            iTemp = w[i - 1];
            if (i % Nk == 0) {
                iTemp = subWord(rotWord(iTemp)) ^ Rcon[i / Nk];
            } else if (Nk > 6 && i % Nk == 4) {
                iTemp = subWord(iTemp);
            } // end if
            w[i] = w[i - Nk] ^ iTemp;
            i++;
        } // end while
    }

    /**
     * create a key expansion for specified key(byte array)
     * @param key byte[] AES key
     * @return int[] AES key expansion
     */
    public int[] createKeyExpansion(byte key[]) {
        int w[] = new int[Nb * (Nr + 1)];
        keyExpansion(key, w);
        return w;
    }

    public byte[] createKey() {
        byte key[] = new byte[4 * Nk];
        java.util.Random rndGen = new java.util.Random();
        rndGen.nextBytes(key);
        return key;
    }

    /**
     * decrypt the input message (bytesMessage)
     * the procedure is use aes to decrypt and then get the message form the packet.
     * the packet format listed below:
     * |message size|version of richard AES|message body|
     * 0------------7---------------------11-------------
     * we need to record message size becord aes is a block cipher algorithm,
     * if you don't remember the original message size, you might get lot of 0x00 at your decrypted message.
     * @param bytesMessage byte[] message(encrypted) which will be decrypted
     * @param wordsKeyExpansion int[] key expansion array (generated by key byte array)
     * @return byte[] the decrypted bytes array
     */
    public byte[] invCipher(byte bytesMessage[], int wordsKeyExpansion[]) {
        AESBlocks abk = new AESBlocks(bytesMessage);
        AESBlocks abkDecrypted = new AESBlocks(abk.getDataLength());

        byte out[][];
        for (int i = 0; i < abk.size(); i++) {
            out = this.invCipher(abk.getBlock(i), wordsKeyExpansion);
            abkDecrypted.addBlock(out);
        }

        // extract message size to lPacketSize
        byte bytesPacket[] = abkDecrypted.getBytes();
        long lPacketSize = (((long)bytesPacket[7]) << 56) & 0xFF00000000000000l;
        lPacketSize = lPacketSize | ((((long)bytesPacket[6]) << 48)&0x00FF000000000000l);
        lPacketSize = lPacketSize | ((((long)bytesPacket[5]) << 40)&0x0000FF0000000000l);
        lPacketSize = lPacketSize | ((((long)bytesPacket[4]) << 32)&0x000000FF00000000l);
        lPacketSize = lPacketSize | ((((long)bytesPacket[3]) << 24)&0x00000000FF000000l);
        lPacketSize = lPacketSize | ((((long)bytesPacket[2]) << 16)&0x0000000000FF0000l);
        lPacketSize = lPacketSize | ((((long)bytesPacket[1]) << 8)&0x000000000000FF00l);
        lPacketSize = lPacketSize | (((long)bytesPacket[0])&0x00000000000000FFl);

        // extract version to iVersion
        int iVersion = (((int)bytesPacket[11]) << 24) & 0xFF000000;
        iVersion = iVersion | ((((int)bytesPacket[10]) << 16) & 0x00FF0000);
        iVersion = iVersion | ((((int)bytesPacket[9] ) << 8 ) & 0x0000FF00);
        iVersion = iVersion | (( (int)bytesPacket[8] ) & 0x000000FF);   
        /*
        if (this.m_version != iVersion) {
            // should do something if version conflict
            // but current is no need to process
        }
        */


        // retreve messages form packet
        byte bytesResult[] = new byte[(int)lPacketSize];
        for (int i=0; i<bytesResult.length; i++) {
            bytesResult[i] = bytesPacket[i+12];
        }

        return bytesResult;
    }

    /**
     * decrypt the input message (bytesMessage)
     * @param bytesMessage byte[][] message(encrypted) which will be decrypted
     * @param wordsKeyExpansion int[] key expansion array (generated by key byte array)
     * @return byte[][]
     */
    private byte[][] invCipher(byte bytesMessage[][], int wordsKeyExpansion[]) {
        byte state[][] = new byte[4][Nb];
        state = bytesMessage;
        //strTrace = "";

        //strTrace += AESMessage.getTrace("Inverse Cipher Started Initial state", state); // debug trace
        state = addRoundKey(state, wordsKeyExpansion, Nr * Nb);
        //strTrace += AESMessage.getTrace("After addRoundKey", state); // debug trace

        for (int round = (Nr - 1); round >= 1; round--) {
            //strTrace += AESMessage.getTrace("Round " + round + " started!"); // debug trace
            state = invShiftRows(state);
            //strTrace += AESMessage.getTrace("After invShiftRows", state); // debug trace
            state = invSubBytes(state);
            //strTrace += AESMessage.getTrace("After invSubBytes", state); // debug trace
            state = addRoundKey(state, wordsKeyExpansion, round * Nb);
            //strTrace += AESMessage.getTrace("After addRoundKey", state); // debug trace
            state = invMixColumns(state);
            //strTrace += AESMessage.getTrace("After invMixColumns", state); // debug trace
        }
        state = invShiftRows(state);
        //strTrace += AESMessage.getTrace("After invShiftRows", state); // debug trace
        state = invSubBytes(state);
        //strTrace += AESMessage.getTrace("After invSubBytes", state); // debug trace
        state = addRoundKey(state, wordsKeyExpansion, 0);
        //strTrace += AESMessage.getTrace("After addRoundKey", state); // debug trace

        return state;
    }

    private byte[][] invShiftRows(byte state[][]) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        // r=0 is not shifted
        stateNew[0] = state[0];
        for (int r = 1; r < state.length; r++)
            for (int c = 0; c < state[r].length; c++)
                stateNew[r][(c + shift(r, Nb)) % Nb] = state[r][c];

        return stateNew;
    }

    private static byte[][] invSubBytes(byte state[][]) {
        for (int i = 0; i < state.length; i++)
            for (int j = 0; j < state[i].length; j++)
                state[i][j] = invSboxTransform(state[i][j]);
        return state;
    }

    private static byte invSboxTransform(byte value) {
        byte bUpper = 0, bLower = 0;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return sboxInv[bUpper][bLower];
    }

    private byte[][] invMixColumns(byte state[][]) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        for (int c = 0; c < Nb; c++) {
            stateNew[0][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x0e),
                    finiteMultiplication(state[1][c], 0x0b),
                    finiteMultiplication(state[2][c], 0x0d),
                    finiteMultiplication(state[3][c], 0x09));
            stateNew[1][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x09),
                    finiteMultiplication(state[1][c], 0x0e),
                    finiteMultiplication(state[2][c], 0x0b),
                    finiteMultiplication(state[3][c], 0x0d));
            stateNew[2][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x0d),
                    finiteMultiplication(state[1][c], 0x09),
                    finiteMultiplication(state[2][c], 0x0e),
                    finiteMultiplication(state[3][c], 0x0b));
            stateNew[3][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x0b),
                    finiteMultiplication(state[1][c], 0x0d),
                    finiteMultiplication(state[2][c], 0x09),
                    finiteMultiplication(state[3][c], 0x0e));
        }
        return stateNew;

    }

    /**
     * <p>Title: AESBlocks</p>
     *
     * <p>Description: AESBlocks is an inner class, which act as an Value Object. It is the block array which defined in AES RFC</p>
     *
     * @author Richard
     * @version 1.0
     */
    public class AESBlocks {
        public AESBlocks(long originalDataLength) {
            m_listBlocks = new ArrayList();
            m_originalDataLength = originalDataLength;
        }

        private List m_listBlocks;
        private long m_originalDataLength = 0;

        private void initBlocks(byte[] bytesMessage) {
            int Nb = AESAlgorithm.NB_VALUE;
            m_listBlocks = new ArrayList((bytesMessage.length % (4 * Nb)) + 1);

            int iRow = 0, iColumn = 0, i = 1;
            byte block[][] = new byte[4][Nb];
            block[0][0] = bytesMessage[0];

            // 記錄原來的字串長度
            m_originalDataLength = bytesMessage.length;

            boolean bBlockAlreadyAdded = false;

            for (i = 1; i < bytesMessage.length; i++) {
                if (i % (4 * Nb) == 0) {
                    m_listBlocks.add(block);
                    bBlockAlreadyAdded = true;
                    block = new byte[4][Nb];
                }
                iRow = i % Nb;
                iColumn = (i / 4) % Nb;
                block[iColumn][iRow] = bytesMessage[i];
                bBlockAlreadyAdded = false;
            } // end for

            if (!bBlockAlreadyAdded)
                m_listBlocks.add(block);
        }

        public AESBlocks(byte[] bytesMessage) {
            initBlocks(bytesMessage);
        }

        public AESBlocks(String sMessage) {
            try {
                initBlocks(sMessage.getBytes(DEFAULT_CHARSET));
            } catch (UnsupportedEncodingException ex) {
                throw new RuntimeException("the charset: " + DEFAULT_CHARSET +
                        " is not supported!", ex);
            }
        }

        public int size() {
            return m_listBlocks.size();
        }

        public long getDataLength() {
            return m_originalDataLength;
        }

        public byte getValue(int iBlockIndex, int iColumn, int iRow) {
            return ((byte[][]) m_listBlocks.get(iBlockIndex))[iColumn][iRow];
        }

        public void setValue(int iBlockIndex, int iColumn, int iRow, byte value) {
            ((byte[][]) m_listBlocks.get(iBlockIndex))[iColumn][iRow] = value;
        }

        public byte[][] getBlock(int iBlockIndex) {
            return (byte[][]) m_listBlocks.get(iBlockIndex);
        }

        public void addBlock(byte[][] block) {
            m_listBlocks.add(block);
        }

        public String toString() {
            try {
                return (new String(this.getBytes(), DEFAULT_CHARSET));
            } catch (UnsupportedEncodingException ex) {
                throw new RuntimeException("the charset: " + DEFAULT_CHARSET +
                        " is not supported!", ex);
            }
        }

        public byte[] getBytes() {
            int Nb = AESAlgorithm.NB_VALUE;

            int iBlockSize = 4 * Nb;
            byte[] bytes = new byte[iBlockSize * this.m_listBlocks.size()];

            int iCursor = 0;
            Iterator iter = m_listBlocks.iterator();
            while (iter.hasNext()) {
                byte[][] block = (byte[][]) iter.next();
                for (int i = 0; i < iBlockSize; i++) {
                    int iRow = i % 4;
                    int iCol = (i / 4) % 4;

                    //if ( (iCursor+i) >= m_originalDataLength ) {
                    //  break;
                    //}
                    bytes[iCursor + i] = block[iCol][iRow];
                }
                iCursor += iBlockSize;
            }
            return bytes;
        }

    } // end class AESBlocks

}