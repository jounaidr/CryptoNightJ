import keccak.Keccak1600;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;

public class KeccakUtils {

    public static byte[] keccak1600(String in){
        Keccak1600 keccakHasher = new Keccak1600(in);
        return keccakHasher.digestArray();
    }

    public static byte[] permutation(byte[] in){
        //Convert byte array input into 32byte int array
        IntBuffer intBuf = ByteBuffer.wrap(in).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
        int[] state = new int[intBuf.remaining()];
        intBuf.get(state);

        int h, l, n, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9,
                b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17,
                b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31, b32, b33,
                b34, b35, b36, b37, b38, b39, b40, b41, b42, b43, b44, b45, b46, b47, b48, b49;

        long[] RC = new long[]{1L, 0L, 32898L, 0L, 32906L, 2147483648L, 2147516416L, 2147483648L, 32907L, 0L, 2147483649L,
                0L, 2147516545L, 2147483648L, 32777L, 2147483648L, 138L, 0L, 136L, 0L, 2147516425L, 0L,
                2147483658L, 0L, 2147516555L, 0L, 139L, 2147483648L, 32905L, 2147483648L, 32771L,
                2147483648L, 32770L, 2147483648L, 128L, 2147483648L, 32778L, 0L, 2147483658L, 2147483648L,
                2147516545L, 2147483648L, 32896L, 2147483648L, 2147483649L, 0L, 2147516424L, 2147483648L};

        for (n = 0; n < 48; n += 2) {
            c0 = state[0] ^ state[10] ^ state[20] ^ state[30] ^ state[40];
            c1 = state[1] ^ state[11] ^ state[21] ^ state[31] ^ state[41];
            c2 = state[2] ^ state[12] ^ state[22] ^ state[32] ^ state[42];
            c3 = state[3] ^ state[13] ^ state[23] ^ state[33] ^ state[43];
            c4 = state[4] ^ state[14] ^ state[24] ^ state[34] ^ state[44];
            c5 = state[5] ^ state[15] ^ state[25] ^ state[35] ^ state[45];
            c6 = state[6] ^ state[16] ^ state[26] ^ state[36] ^ state[46];
            c7 = state[7] ^ state[17] ^ state[27] ^ state[37] ^ state[47];
            c8 = state[8] ^ state[18] ^ state[28] ^ state[38] ^ state[48];
            c9 = state[9] ^ state[19] ^ state[29] ^ state[39] ^ state[49];

            h = c8 ^ ((c2 << 1) | (c3 >>> 31));
            l = c9 ^ ((c3 << 1) | (c2 >>> 31));
            state[0] ^= h;
            state[1] ^= l;
            state[10] ^= h;
            state[11] ^= l;
            state[20] ^= h;
            state[21] ^= l;
            state[30] ^= h;
            state[31] ^= l;
            state[40] ^= h;
            state[41] ^= l;
            h = c0 ^ ((c4 << 1) | (c5 >>> 31));
            l = c1 ^ ((c5 << 1) | (c4 >>> 31));
            state[2] ^= h;
            state[3] ^= l;
            state[12] ^= h;
            state[13] ^= l;
            state[22] ^= h;
            state[23] ^= l;
            state[32] ^= h;
            state[33] ^= l;
            state[42] ^= h;
            state[43] ^= l;
            h = c2 ^ ((c6 << 1) | (c7 >>> 31));
            l = c3 ^ ((c7 << 1) | (c6 >>> 31));
            state[4] ^= h;
            state[5] ^= l;
            state[14] ^= h;
            state[15] ^= l;
            state[24] ^= h;
            state[25] ^= l;
            state[34] ^= h;
            state[35] ^= l;
            state[44] ^= h;
            state[45] ^= l;
            h = c4 ^ ((c8 << 1) | (c9 >>> 31));
            l = c5 ^ ((c9 << 1) | (c8 >>> 31));
            state[6] ^= h;
            state[7] ^= l;
            state[16] ^= h;
            state[17] ^= l;
            state[26] ^= h;
            state[27] ^= l;
            state[36] ^= h;
            state[37] ^= l;
            state[46] ^= h;
            state[47] ^= l;
            h = c6 ^ ((c0 << 1) | (c1 >>> 31));
            l = c7 ^ ((c1 << 1) | (c0 >>> 31));
            state[8] ^= h;
            state[9] ^= l;
            state[18] ^= h;
            state[19] ^= l;
            state[28] ^= h;
            state[29] ^= l;
            state[38] ^= h;
            state[39] ^= l;
            state[48] ^= h;
            state[49] ^= l;

            b0 = state[0];
            b1 = state[1];
            b32 = (state[11] << 4) | (state[10] >>> 28);
            b33 = (state[10] << 4) | (state[11] >>> 28);
            b14 = (state[20] << 3) | (state[21] >>> 29);
            b15 = (state[21] << 3) | (state[20] >>> 29);
            b46 = (state[31] << 9) | (state[30] >>> 23);
            b47 = (state[30] << 9) | (state[31] >>> 23);
            b28 = (state[40] << 18) | (state[41] >>> 14);
            b29 = (state[41] << 18) | (state[40] >>> 14);
            b20 = (state[2] << 1) | (state[3] >>> 31);
            b21 = (state[3] << 1) | (state[2] >>> 31);
            b2 = (state[13] << 12) | (state[12] >>> 20);
            b3 = (state[12] << 12) | (state[13] >>> 20);
            b34 = (state[22] << 10) | (state[23] >>> 22);
            b35 = (state[23] << 10) | (state[22] >>> 22);
            b16 = (state[33] << 13) | (state[32] >>> 19);
            b17 = (state[32] << 13) | (state[33] >>> 19);
            b48 = (state[42] << 2) | (state[43] >>> 30);
            b49 = (state[43] << 2) | (state[42] >>> 30);
            b40 = (state[5] << 30) | (state[4] >>> 2);
            b41 = (state[4] << 30) | (state[5] >>> 2);
            b22 = (state[14] << 6) | (state[15] >>> 26);
            b23 = (state[15] << 6) | (state[14] >>> 26);
            b4 = (state[25] << 11) | (state[24] >>> 21);
            b5 = (state[24] << 11) | (state[25] >>> 21);
            b36 = (state[34] << 15) | (state[35] >>> 17);
            b37 = (state[35] << 15) | (state[34] >>> 17);
            b18 = (state[45] << 29) | (state[44] >>> 3);
            b19 = (state[44] << 29) | (state[45] >>> 3);
            b10 = (state[6] << 28) | (state[7] >>> 4);
            b11 = (state[7] << 28) | (state[6] >>> 4);
            b42 = (state[17] << 23) | (state[16] >>> 9);
            b43 = (state[16] << 23) | (state[17] >>> 9);
            b24 = (state[26] << 25) | (state[27] >>> 7);
            b25 = (state[27] << 25) | (state[26] >>> 7);
            b6 = (state[36] << 21) | (state[37] >>> 11);
            b7 = (state[37] << 21) | (state[36] >>> 11);
            b38 = (state[47] << 24) | (state[46] >>> 8);
            b39 = (state[46] << 24) | (state[47] >>> 8);
            b30 = (state[8] << 27) | (state[9] >>> 5);
            b31 = (state[9] << 27) | (state[8] >>> 5);
            b12 = (state[18] << 20) | (state[19] >>> 12);
            b13 = (state[19] << 20) | (state[18] >>> 12);
            b44 = (state[29] << 7) | (state[28] >>> 25);
            b45 = (state[28] << 7) | (state[29] >>> 25);
            b26 = (state[38] << 8) | (state[39] >>> 24);
            b27 = (state[39] << 8) | (state[38] >>> 24);
            b8 = (state[48] << 14) | (state[49] >>> 18);
            b9 = (state[49] << 14) | (state[48] >>> 18);

            state[0] = (b0 ^ (~b2 & b4));
            state[1] = (b1 ^ (~b3 & b5));
            state[10] = (b10 ^ (~b12 & b14));
            state[11] = (b11 ^ (~b13 & b15));
            state[20] = (b20 ^ (~b22 & b24));
            state[21] = (b21 ^ (~b23 & b25));
            state[30] = (b30 ^ (~b32 & b34));
            state[31] = (b31 ^ (~b33 & b35));
            state[40] = (b40 ^ (~b42 & b44));
            state[41] = (b41 ^ (~b43 & b45));
            state[2] = (b2 ^ (~b4 & b6));
            state[3] = (b3 ^ (~b5 & b7));
            state[12] = (b12 ^ (~b14 & b16));
            state[13] = (b13 ^ (~b15 & b17));
            state[22] = (b22 ^ (~b24 & b26));
            state[23] = (b23 ^ (~b25 & b27));
            state[32] = (b32 ^ (~b34 & b36));
            state[33] = (b33 ^ (~b35 & b37));
            state[42] = (b42 ^ (~b44 & b46));
            state[43] = (b43 ^ (~b45 & b47));
            state[4] = (b4 ^ (~b6 & b8));
            state[5] = (b5 ^ (~b7 & b9));
            state[14] = (b14 ^ (~b16 & b18));
            state[15] = (b15 ^ (~b17 & b19));
            state[24] = (b24 ^ (~b26 & b28));
            state[25] = (b25 ^ (~b27 & b29));
            state[34] = (b34 ^ (~b36 & b38));
            state[35] = (b35 ^ (~b37 & b39));
            state[44] = (b44 ^ (~b46 & b48));
            state[45] = (b45 ^ (~b47 & b49));
            state[6] = (b6 ^ (~b8 & b0));
            state[7] = (b7 ^ (~b9 & b1));
            state[16] = (b16 ^ (~b18 & b10));
            state[17] = (b17 ^ (~b19 & b11));
            state[26] = (b26 ^ (~b28 & b20));
            state[27] = (b27 ^ (~b29 & b21));
            state[36] = (b36 ^ (~b38 & b30));
            state[37] = (b37 ^ (~b39 & b31));
            state[46] = (b46 ^ (~b48 & b40));
            state[47] = (b47 ^ (~b49 & b41));
            state[8] = (b8 ^ (~b0 & b2));
            state[9] = (b9 ^ (~b1 & b3));
            state[18] = (b18 ^ (~b10 & b12));
            state[19] = (b19 ^ (~b11 & b13));
            state[28] = (b28 ^ (~b20 & b22));
            state[29] = (b29 ^ (~b21 & b23));
            state[38] = (b38 ^ (~b30 & b32));
            state[39] = (b39 ^ (~b31 & b33));
            state[48] = (b48 ^ (~b40 & b42));
            state[49] = (b49 ^ (~b41 & b43));

            state[0] ^= RC[n];
            state[1] ^= RC[n + 1];
        }

        //Convert state back into byte array before returning
        byte[] out = new byte[state.length * 4];
        ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().put(state);

        return out;
    }
}
