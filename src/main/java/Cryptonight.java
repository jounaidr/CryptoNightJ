import cryptohashes.BLAKE256;
import cryptohashes.Groestl256;
import cryptohashes.JH256;
import cryptohashes.Skein256;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class Cryptonight {
    private byte[] out;

    public Cryptonight(String inputData) {
        //*******************************************************************
        //                    SCRATCHPAD INITIALISATION
        //*******************************************************************

        //Initialise 2mb scratch pad
        byte[] scratchPad = new byte[2097152];
        //Hash input data with Keccak-1600 to produce 200 byte 'final state'
        byte[] finalState = KeccakUtils.keccak1600(inputData);

        //Extract first 32 bytes of the final state and expand to produce 10 16 byte round keys,
        //and format round keys as a 10x16 2D array
        byte[] expandedKeys = AesUtils.expandRoundKeys(Arrays.copyOfRange(finalState, 0, 32),10);
        byte[][] keys = new byte[10][16];
        for (int i = 0; i < 10; ++i){
            System.arraycopy(expandedKeys, 16 * i, keys[i], 0, 16);
        }

        //Extract bytes 64 to 191 of the final state and format into 8 16 byte blocks (as 2D array)
        byte[][] blocks = new byte[8][16];
        for (int i = 0; i < 8; ++i){
            System.arraycopy(finalState, 64 + 16 * i, blocks[i], 0, 16);
        }

        //Encrypt blocks over and over again with 'aes_round' (with 10 keys generated previously),
        //and write each 128 bytes produced to the scratchpad consecutively,
        //where 'aes_round' carries out SubBytes, ShiftRows and MixColumns steps from AES specification
        for(int i = 0; i < 16384; i++){
            //For each of the 8 blocks, apply 'aes_round' to each block with the 10 generated round keys
            for (int j = 0; j < 8; ++j){
                for (int k = 0; k < 10; ++k) {
                    blocks[j] = AesUtils.aesRound(blocks[j], keys[k]);
                }
            }
            //Write the encrypted blocks to the 128 bytes in the scratch pad from position i
            for (int j = 0; j < 8; ++j){
                System.arraycopy(blocks[j], 0, scratchPad, i*128 + j*16, 16);
            }
        }

        //*******************************************************************
        //                         MEMORY-HARD LOOP
        //*******************************************************************

        //Extract bytes 0 to 31 as 'finalState1', and bytes 32 to 63 as 'finalState2',
        //and xor them, with the first 16 bytes of the result being assigned to 'a' and
        //the rest assigned to 'b'
        byte[] finalState1 = Arrays.copyOfRange(finalState, 0, 32);
        byte[] finalState2 = Arrays.copyOfRange(finalState, 32, 64);
        byte[] abXor = ByteUtils.xor(finalState1, finalState2);
        byte[] a = Arrays.copyOfRange(abXor, 0, 16);
        byte[] b = Arrays.copyOfRange(abXor, 16, 32);

        //Memory-hard loop constantly reads and writes to scratchpad which is more effectively
        //done on the CPU as L3 cache is generally 2mb (and ASICS/GPU generally having memory bottleneck)
        for (int i = 0; i < 524288; ++i){
            int scratchpad_address = toScratchpadAddress(a);
            byte[] scratchpad_aes = AesUtils.aesRound(Arrays.copyOfRange(scratchPad, scratchpad_address, scratchpad_address + 16), a);

            System.arraycopy(scratchpad_aes,0, scratchPad, scratchpad_address, 16);

            byte[] xorB = ByteUtils.xor(b, scratchpad_aes);

            System.arraycopy(xorB, 0, scratchPad, scratchpad_address, 16);

            b = scratchpad_aes;

            scratchpad_address = toScratchpadAddress(b);

            byte[] mul = f8byteMul(b, Arrays.copyOfRange(scratchPad, scratchpad_address, scratchpad_address + 8));

            a = f8byteAdd(a, mul);

            byte[] xorA = ByteUtils.xor(a, Arrays.copyOfRange(scratchPad, scratchpad_address, scratchpad_address + 16));

            System.arraycopy(a, 0, scratchPad, scratchpad_address, 16);

            a = xorA;
        }

        byte[] key_2 = new byte[32];
        System.arraycopy(finalState, 32, key_2, 0, 32);

        byte[] expandedKeys_2 = AesUtils.expandRoundKeys(key_2,10);
        byte[][] keys_2 = new byte[10][16];
        for (int i = 0; i < 10; ++i){
            System.arraycopy(expandedKeys_2, 16 * i, keys_2[i], 0, 16);
        }

        byte[] keccakXorAes = new byte[128];
        System.arraycopy(finalState, 64, keccakXorAes, 0, 128);

        for(int i = 0; i < 16384; i++) {
            keccakXorAes = ByteUtils.xor(keccakXorAes, Arrays.copyOfRange(scratchPad, i * 128, (i * 128) + 128));

            byte[][] blocks_2 = new byte[8][16];
            for (int j = 0; j < 8; ++j){
                System.arraycopy(keccakXorAes, 16 * j, blocks_2[j], 0, 16);
            }

            for (int j = 0; j < 8; ++j){
                for (int k = 0; k < 10; ++k) {
                    blocks_2[j] = AesUtils.aesRound(blocks_2[j], keys_2[k]);
                }
                System.arraycopy(blocks_2[j], 0, keccakXorAes, j*16, 16);
            }
        }

        System.arraycopy(keccakXorAes, 0, finalState, 64, 128);

        byte[] modifiedState = KeccakUtils.permutation(finalState);

        int lastHashType = (modifiedState[0] & 0xFF) & 3;

        switch(lastHashType) {
            case 0: // BLAKE-256
                BLAKE256 blake256 = new BLAKE256();
                out = blake256.digest(modifiedState);
                break;
            case 1: // GROESTL-256
                Groestl256 groestl256 = new Groestl256();
                out = groestl256.digest(modifiedState);
                break;
            case 2: // JH-256
                JH256 jh256 = new JH256();
                out = jh256.digest(modifiedState);
                break;
            case 3: // SKEIN-256
                Skein256 skein256 = new Skein256();
                out = skein256.digest(modifiedState);
                break;
        }
    }

    public byte[] returnHash(){
        return out;
    }

    private int toScratchpadAddress(byte[] a) {
        // When a 16-byte value needs to be converted into an address in the scratchpad, it is
        // interpreted as a little-endian integer, and the 21 low-order bits are
        // used as a byte index. However, the 4 low-order bits of the index are
        // cleared to ensure the 16-byte alignment.
        return ((a[0] & 0xFF) >> 4) << 4 | ((a[1] & 0xFF) << 8) |(((a[2] & 0xFF) & 0x1F) << 16);
    }

    private byte[] f8byteMul(byte[] lea, byte[] leb) {
        // The 8byte_mul function, however, uses only the first 8 bytes of each
        // argument, which are interpreted as unsigned 64-bit little-endian
        // integers and multiplied together. The result is converted into 16
        // bytes, and finally the two 8-byte halves of the result are swapped.
        // var lea = new Uint16Array(a.buffer);
        // var leb = new Uint16Array(b.buffer);

        short[] lea_short = new short[lea.length/2];
        short[] leb_short = new short[leb.length/2];

        ByteBuffer.wrap(lea).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(lea_short);
        ByteBuffer.wrap(leb).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(leb_short);

        short[] res16 = new short[8];

        for(int i = 0; i < 4; i++) {
            // multiply
            int carry = 0;
            for(int j = 0; j < 4; j++) {
                int m = (lea_short[i] & 0xFFFF) * (leb_short[j] & 0xFFFF) + carry;
                int s = (res16[j + i] & 0xFFFF) + m;
                res16[j + i] = (short)(s & 0xFFFF);
                carry = s >>> 16;
            }
            int ind = 4 + i;
            while(carry > 0 && ind < 8) {
                int s = (res16[ind] & 0xFFFF) + carry;
                res16[ind] = (short)(s & 0xFFFF);
                carry = s >>> 16;
                ind++;
            }
        }

        short[] res16Swap = new short[8];
        System.arraycopy(res16, 0, res16Swap, 4, 4);
        System.arraycopy(res16, 4, res16Swap, 0, 4);

        byte[] res = new byte[res16Swap.length * 2];
        ByteBuffer.wrap(res).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().put(res16Swap);

        return res;
    }

    private byte[] f8byteAdd(byte[] a, byte[] b) {
        // Where, the 8byte_add function represents each of the arguments as a
        // pair of 64-bit little-endian values and adds them together,
        // component-wise, modulo 2^64. The result is converted back into 16
        // bytes.
        byte[] lea1 = new byte[]{a[15], a[14], a[13], a[12], a[11], a[10], a[9], a[8]};
        byte[] lea2 = new byte[]{a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0]};
        byte[] leb1 = new byte[]{b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8]};
        byte[] leb2 = new byte[]{b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]};

        int carry = 0;
        byte[] addition1 = new byte[8];
        for(int i = 7; i >= 0; i--) {
            int s = (lea1[i] & 0xFF) + (leb1[i] & 0xFF) + carry;
            addition1[i] = (byte)(s % 0x100);
            carry = (int) Math.floor(s/ (double)0x100);
        }

        carry = 0;
        byte[] addition2 = new byte[8];
        for(int i = 7; i >= 0; i--) {
            int s = (lea2[i] & 0xFF) + (leb2[i] & 0xFF) + carry;
            addition2[i] = (byte)(s % 0x100);
            carry = (int) (int) Math.floor(s/ (double)0x100);
        }

        byte[] res = new byte[16];
        for(int i = 0; i < 8; i++) {
            res[15 - i] = addition1[i];
        }
        for(int i = 0; i < 8; i++) {
            res[7 - i] = addition2[i];
        }
        return res;
    }
}
