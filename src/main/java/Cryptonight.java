import aes.AESAlgorithm;
import aes.Aes;
import aes.ByteUtils;
import aes.HashDirection;

import fr.cryptohash.BLAKE256;
import fr.cryptohash.Groestl256;
import fr.cryptohash.JH256;
import fr.cryptohash.Skein256;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jcajce.provider.digest.GOST3411;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Cryptonight {
    private byte[] out;

    public Cryptonight(String inputData) {
        Keccak1600 keccakHasher = new Keccak1600(inputData);
        byte[] keccakInput = keccakHasher.digestArray();

        byte[] scratchPad = new byte[2097152];

        //Make key
        byte[] key = new byte[32];
        System.arraycopy(keccakInput, 0, key, 0, 32);

        //Round keys
        Aes aes = new Aes();
        byte[] expandedKeys = aes.expandRoundKeys(key,10, HashDirection.ENCRYPT);
        byte[][] keys = new byte[10][16];
        for (int i = 0; i < 10; ++i){
            System.arraycopy(expandedKeys, 16 * i, keys[i], 0, 16);
        }


        //Make blocks
        byte[][] blocks = new byte[8][16];
        for (int i = 0; i < 8; ++i){
            System.arraycopy(keccakInput, 64 + 16 * i, blocks[i], 0, 16);
        }


        AESAlgorithm test = new AESAlgorithm();

        for(int pos = 0; pos < 16384; pos++){

            for (int i = 0; i < 8; ++i){
                for (int j = 0; j < 10; ++j) {
                    blocks[i] = test.aesRound(blocks[i], keys[j]);
                }
            }

            for (int i = 0; i < 8; ++i){
                System.arraycopy(blocks[i], 0, scratchPad, pos*128 + i*16, 16);
            }
        }

        byte[] finalState1 = Arrays.copyOfRange(keccakInput, 0, 32);
        byte[] finalState2 = Arrays.copyOfRange(keccakInput, 32, 64);
        byte[] abXor = ByteUtils.xor(finalState1, finalState2);
        byte[] a = Arrays.copyOfRange(abXor, 0, 16);
        byte[] b = Arrays.copyOfRange(abXor, 16, 32);

//        byte [] weet = f8byte_mul(a,b);
//
//        int x = to_scratchpad_address(a);


        for (int i = 0; i < 524288; ++i){
            int scratchpad_address = to_scratchpad_address(a);
            byte[] scratchpad_aes = test.aesRound(Arrays.copyOfRange(scratchPad, scratchpad_address, scratchpad_address + 16), a);

            System.arraycopy(scratchpad_aes,0, scratchPad, scratchpad_address, 16);

            byte[] xorB = ByteUtils.xor(b, scratchpad_aes);

            System.arraycopy(xorB, 0, scratchPad, scratchpad_address, 16);

            b = scratchpad_aes;

            scratchpad_address = to_scratchpad_address(b);

            byte[] mul = f8byte_mul(b, Arrays.copyOfRange(scratchPad, scratchpad_address, scratchpad_address + 8));

            a = f8byte_add(a, mul);

            byte[] xorA = ByteUtils.xor(a, Arrays.copyOfRange(scratchPad, scratchpad_address, scratchpad_address + 16));

            System.arraycopy(a, 0, scratchPad, scratchpad_address, 16);

            a = xorA;
        }

        byte[] key_2 = new byte[32];
        System.arraycopy(keccakInput, 32, key_2, 0, 32);

        byte[] expandedKeys_2 = aes.expandRoundKeys(key_2,10, HashDirection.ENCRYPT);
        byte[][] keys_2 = new byte[10][16];
        for (int i = 0; i < 10; ++i){
            System.arraycopy(expandedKeys_2, 16 * i, keys_2[i], 0, 16);
        }

        byte[] keccakXorAes = new byte[128];
        System.arraycopy(keccakInput, 64, keccakXorAes, 0, 128);

        for(int i = 0; i < 16384; i++) {
            keccakXorAes = ByteUtils.xor(keccakXorAes, Arrays.copyOfRange(scratchPad, i * 128, (i * 128) + 128));

            byte[][] blocks_2 = new byte[8][16];
            for (int j = 0; j < 8; ++j){
                System.arraycopy(keccakXorAes, 16 * j, blocks_2[j], 0, 16);
            }

            for (int j = 0; j < 8; ++j){
                for (int k = 0; k < 10; ++k) {
                    blocks_2[j] = test.aesRound(blocks_2[j], keys_2[k]);
                }
                System.arraycopy(blocks_2[j], 0, keccakXorAes, j*16, 16);
            }
        }

        System.arraycopy(keccakXorAes, 0, keccakInput, 64, 128);



        IntBuffer intBuf = ByteBuffer.wrap(keccakInput).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
        int[] keccak_int = new int[intBuf.remaining()];
        intBuf.get(keccak_int);

        keccak_int = keccakHasher.permutation(keccak_int);

        byte[] bytes2 = new byte[keccak_int.length * 4];
        ByteBuffer.wrap(bytes2).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().put(keccak_int);

//        long[] keccak_long = new long[keccakInput.length/8];
//        ByteBuffer.wrap(keccakInput).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().get(keccak_long);
//
//        keccak_long = keccakHasher.permutation(keccak_long);
//        byte[] keccakOut = new byte[keccak_long.length * 8];
//
//        ByteBuffer.wrap(keccakOut).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().put(keccak_long);
//

        int lastHashType = (bytes2[0] & 0xFF) >> 6;


        byte[] result;

        switch(lastHashType) {
            case 0: // BLAKE-256
                BLAKE256 blake256 = new BLAKE256();
                result = blake256.digest(bytes2);
                break;
            case 1: // GROESTL-256
                Groestl256 groestl256 = new Groestl256();
                result = groestl256.digest(bytes2);
                break;
            case 2: // JH-256
                JH256 jh256 = new JH256();
                result = jh256.digest(bytes2);
                break;
            case 3: // SKEIN-256
                Skein256 skein256 = new Skein256();
                result = skein256.digest(bytes2);
                break;
        }


        BLAKE256 blake256 = new BLAKE256();
        result = blake256.digest(bytes2);

        String test123 = new String(Hex.encode(result));

        return;


//        byte[][] keys = new byte[11][];
//        keys[0]=key;
//        for (int i = 0; i < 10; ++i) {
//            keys[i+1]=new byte[32];
//            Rijndael.expandKey(keys[i], keys[i+1], 0, 32, 32);
//        }

        //byte[] pad = new byte[2097152];

        //Encrypt blocks

//        for (int bid = 0; bid < 8; ++bid) {
//            for (int i = 0; i < 10; ++i) {
//                blocks[bid] = AES.encrypt(blocks[i], keys[i+1]);
//            }
//        }

//        return Utils.byteToHex(out);
    }

    public byte[] returnHash(){
        return null;
    }

    private int to_scratchpad_address(byte[] a) {
        // When a 16-byte value needs to be converted into an address in the scratchpad, it is
        // interpreted as a little-endian integer, and the 21 low-order bits are
        // used as a byte index. However, the 4 low-order bits of the index are
        // cleared to ensure the 16-byte alignment.
        return ((a[0] & 0xFF) >> 4) << 4 | ((a[1] & 0xFF) << 8) |(((a[2] & 0xFF) & 0x1F) << 16);
    }

    private byte[] f8byte_mul(byte[] lea, byte[] leb) {
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

//        for(int i = 0; i < 8; i++){
//            res16.put(i, (byte)0);
//        }

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

        byte[] bytes2 = new byte[res16Swap.length * 2];
        ByteBuffer.wrap(bytes2).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().put(res16Swap);

        // swapping 8 bytes...
//        var res32 = new Uint32Array(res16.buffer);
//        var temp1 = res32[0];
//        var temp2 = res32[1];
//        res32[0] = res32[2];
//        res32[1] = res32[3];
//        res32[2] = temp1;
//        res32[3] = temp2;

        return bytes2;
    }

    private byte[] f8byte_add(byte[] a, byte[] b) {
        // Where, the 8byte_add function represents each of the arguments as a
        // pair of 64-bit little-endian values and adds them together,
        // component-wise, modulo 2^64. The result is converted back into 16
        // bytes.
        byte[] lea1 = new byte[]{a[15], a[14], a[13], a[12], a[11], a[10], a[9], a[8]};
        byte[] lea2 = new byte[]{a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0]};
        byte[] leb1 = new byte[]{b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8]};
        byte[] leb2 = new byte[]{b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]};

//        byte[] lea1 = new byte[]{(byte)(a[15] & 0xFF), (byte)(a[14] & 0xFF), (byte)(a[13] & 0xFF), (byte)(a[12] & 0xFF), (byte)(a[11] & 0xFF), (byte)(a[10] & 0xFF), (byte)(a[9] & 0xFF), (byte)(a[8] & 0xFF)};
//        byte[] lea2 = new byte[]{(byte)(a[7] & 0xFF), (byte)(a[6] & 0xFF), (byte)(a[5] & 0xFF), (byte)(a[4] & 0xFF), (byte)(a[3] & 0xFF), (byte)(a[2] & 0xFF), (byte)(a[1] & 0xFF), (byte)(a[0] & 0xFF)};
//        byte[] leb1 = new byte[]{(byte)(b[15] & 0xFF), (byte)(b[14] & 0xFF), (byte)(b[13] & 0xFF), (byte)(b[12] & 0xFF), (byte)(b[11] & 0xFF), (byte)(b[10] & 0xFF), (byte)(b[9] & 0xFF), (byte)(b[8] & 0xFF)};
//        byte[] leb2 = new byte[]{(byte)(b[7] & 0xFF), (byte)(b[6] & 0xFF), (byte)(b[5] & 0xFF), (byte)(b[4] & 0xFF), (byte)(b[3] & 0xFF), (byte)(b[2] & 0xFF), (byte)(b[1] & 0xFF), (byte)(b[0] & 0xFF)};

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

    private byte[] keccak(String data){
        Keccak1600 keccakHasher = new Keccak1600(data);
        byte[] out = keccakHasher.digestArray();
        return out;
    }

//    private byte[] keccak(byte[] data){
//        Keccak1600 keccakHasher = new Keccak1600(data);
//        byte[] out = keccakHasher.digestArray();
//        return out;
//    }
}
