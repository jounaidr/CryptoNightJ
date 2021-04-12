import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * @author Joseph Robert Melsha (joe.melsha@live.com)
 * @author (MODIFICATIONS) jounaidr (https://github.com/jounaidr/JCryptoNight)
 *
 * Source: https://github.com/jrmelsha/keccak
 * Created: Jun 23, 2016
 *
 * Copyright 2016 Joseph Robert Melsha
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
public class Keccak1600 {
    private static final int MAX_STATE_SIZE = 1600;
    private static final int MAX_STATE_SIZE_WORDS = MAX_STATE_SIZE / 64;

    protected int rateSizeBits, digestSizeBits;
    private long[] state = new long[MAX_STATE_SIZE_WORDS];
    private int rateBits;
    private boolean padded;

    public Keccak1600(String data) {
        for (int i = 0; i < MAX_STATE_SIZE_WORDS; ++i)
            state[i] = 0;
        rateBits = 0;

        this.rateSizeBits = 1088;
        this.digestSizeBits = 512;
        padded = false;

        this.update(data.getBytes());
    }

    public int[] permutation(int[] s){
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
            c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
            c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
            c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
            c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
            c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
            c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
            c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
            c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
            c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
            c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];

            h = c8 ^ ((c2 << 1) | (c3 >>> 31));
            l = c9 ^ ((c3 << 1) | (c2 >>> 31));
            s[0] ^= h;
            s[1] ^= l;
            s[10] ^= h;
            s[11] ^= l;
            s[20] ^= h;
            s[21] ^= l;
            s[30] ^= h;
            s[31] ^= l;
            s[40] ^= h;
            s[41] ^= l;
            h = c0 ^ ((c4 << 1) | (c5 >>> 31));
            l = c1 ^ ((c5 << 1) | (c4 >>> 31));
            s[2] ^= h;
            s[3] ^= l;
            s[12] ^= h;
            s[13] ^= l;
            s[22] ^= h;
            s[23] ^= l;
            s[32] ^= h;
            s[33] ^= l;
            s[42] ^= h;
            s[43] ^= l;
            h = c2 ^ ((c6 << 1) | (c7 >>> 31));
            l = c3 ^ ((c7 << 1) | (c6 >>> 31));
            s[4] ^= h;
            s[5] ^= l;
            s[14] ^= h;
            s[15] ^= l;
            s[24] ^= h;
            s[25] ^= l;
            s[34] ^= h;
            s[35] ^= l;
            s[44] ^= h;
            s[45] ^= l;
            h = c4 ^ ((c8 << 1) | (c9 >>> 31));
            l = c5 ^ ((c9 << 1) | (c8 >>> 31));
            s[6] ^= h;
            s[7] ^= l;
            s[16] ^= h;
            s[17] ^= l;
            s[26] ^= h;
            s[27] ^= l;
            s[36] ^= h;
            s[37] ^= l;
            s[46] ^= h;
            s[47] ^= l;
            h = c6 ^ ((c0 << 1) | (c1 >>> 31));
            l = c7 ^ ((c1 << 1) | (c0 >>> 31));
            s[8] ^= h;
            s[9] ^= l;
            s[18] ^= h;
            s[19] ^= l;
            s[28] ^= h;
            s[29] ^= l;
            s[38] ^= h;
            s[39] ^= l;
            s[48] ^= h;
            s[49] ^= l;

            b0 = s[0];
            b1 = s[1];
            b32 = (s[11] << 4) | (s[10] >>> 28);
            b33 = (s[10] << 4) | (s[11] >>> 28);
            b14 = (s[20] << 3) | (s[21] >>> 29);
            b15 = (s[21] << 3) | (s[20] >>> 29);
            b46 = (s[31] << 9) | (s[30] >>> 23);
            b47 = (s[30] << 9) | (s[31] >>> 23);
            b28 = (s[40] << 18) | (s[41] >>> 14);
            b29 = (s[41] << 18) | (s[40] >>> 14);
            b20 = (s[2] << 1) | (s[3] >>> 31);
            b21 = (s[3] << 1) | (s[2] >>> 31);
            b2 = (s[13] << 12) | (s[12] >>> 20);
            b3 = (s[12] << 12) | (s[13] >>> 20);
            b34 = (s[22] << 10) | (s[23] >>> 22);
            b35 = (s[23] << 10) | (s[22] >>> 22);
            b16 = (s[33] << 13) | (s[32] >>> 19);
            b17 = (s[32] << 13) | (s[33] >>> 19);
            b48 = (s[42] << 2) | (s[43] >>> 30);
            b49 = (s[43] << 2) | (s[42] >>> 30);
            b40 = (s[5] << 30) | (s[4] >>> 2);
            b41 = (s[4] << 30) | (s[5] >>> 2);
            b22 = (s[14] << 6) | (s[15] >>> 26);
            b23 = (s[15] << 6) | (s[14] >>> 26);
            b4 = (s[25] << 11) | (s[24] >>> 21);
            b5 = (s[24] << 11) | (s[25] >>> 21);
            b36 = (s[34] << 15) | (s[35] >>> 17);
            b37 = (s[35] << 15) | (s[34] >>> 17);
            b18 = (s[45] << 29) | (s[44] >>> 3);
            b19 = (s[44] << 29) | (s[45] >>> 3);
            b10 = (s[6] << 28) | (s[7] >>> 4);
            b11 = (s[7] << 28) | (s[6] >>> 4);
            b42 = (s[17] << 23) | (s[16] >>> 9);
            b43 = (s[16] << 23) | (s[17] >>> 9);
            b24 = (s[26] << 25) | (s[27] >>> 7);
            b25 = (s[27] << 25) | (s[26] >>> 7);
            b6 = (s[36] << 21) | (s[37] >>> 11);
            b7 = (s[37] << 21) | (s[36] >>> 11);
            b38 = (s[47] << 24) | (s[46] >>> 8);
            b39 = (s[46] << 24) | (s[47] >>> 8);
            b30 = (s[8] << 27) | (s[9] >>> 5);
            b31 = (s[9] << 27) | (s[8] >>> 5);
            b12 = (s[18] << 20) | (s[19] >>> 12);
            b13 = (s[19] << 20) | (s[18] >>> 12);
            b44 = (s[29] << 7) | (s[28] >>> 25);
            b45 = (s[28] << 7) | (s[29] >>> 25);
            b26 = (s[38] << 8) | (s[39] >>> 24);
            b27 = (s[39] << 8) | (s[38] >>> 24);
            b8 = (s[48] << 14) | (s[49] >>> 18);
            b9 = (s[49] << 14) | (s[48] >>> 18);

            s[0] = (b0 ^ (~b2 & b4));
            s[1] = (b1 ^ (~b3 & b5));
            s[10] = (b10 ^ (~b12 & b14));
            s[11] = (b11 ^ (~b13 & b15));
            s[20] = (b20 ^ (~b22 & b24));
            s[21] = (b21 ^ (~b23 & b25));
            s[30] = (b30 ^ (~b32 & b34));
            s[31] = (b31 ^ (~b33 & b35));
            s[40] = (b40 ^ (~b42 & b44));
            s[41] = (b41 ^ (~b43 & b45));
            s[2] = (b2 ^ (~b4 & b6));
            s[3] = (b3 ^ (~b5 & b7));
            s[12] = (b12 ^ (~b14 & b16));
            s[13] = (b13 ^ (~b15 & b17));
            s[22] = (b22 ^ (~b24 & b26));
            s[23] = (b23 ^ (~b25 & b27));
            s[32] = (b32 ^ (~b34 & b36));
            s[33] = (b33 ^ (~b35 & b37));
            s[42] = (b42 ^ (~b44 & b46));
            s[43] = (b43 ^ (~b45 & b47));
            s[4] = (b4 ^ (~b6 & b8));
            s[5] = (b5 ^ (~b7 & b9));
            s[14] = (b14 ^ (~b16 & b18));
            s[15] = (b15 ^ (~b17 & b19));
            s[24] = (b24 ^ (~b26 & b28));
            s[25] = (b25 ^ (~b27 & b29));
            s[34] = (b34 ^ (~b36 & b38));
            s[35] = (b35 ^ (~b37 & b39));
            s[44] = (b44 ^ (~b46 & b48));
            s[45] = (b45 ^ (~b47 & b49));
            s[6] = (b6 ^ (~b8 & b0));
            s[7] = (b7 ^ (~b9 & b1));
            s[16] = (b16 ^ (~b18 & b10));
            s[17] = (b17 ^ (~b19 & b11));
            s[26] = (b26 ^ (~b28 & b20));
            s[27] = (b27 ^ (~b29 & b21));
            s[36] = (b36 ^ (~b38 & b30));
            s[37] = (b37 ^ (~b39 & b31));
            s[46] = (b46 ^ (~b48 & b40));
            s[47] = (b47 ^ (~b49 & b41));
            s[8] = (b8 ^ (~b0 & b2));
            s[9] = (b9 ^ (~b1 & b3));
            s[18] = (b18 ^ (~b10 & b12));
            s[19] = (b19 ^ (~b11 & b13));
            s[28] = (b28 ^ (~b20 & b22));
            s[29] = (b29 ^ (~b21 & b23));
            s[38] = (b38 ^ (~b30 & b32));
            s[39] = (b39 ^ (~b31 & b33));
            s[48] = (b48 ^ (~b40 & b42));
            s[49] = (b49 ^ (~b41 & b43));

            s[0] ^= RC[n];
            s[1] ^= RC[n + 1];
        }
      return s;
    }

    @Override
    public String toString() {
        return "Keccak-" + digestSizeBits;
    }

    private void update(byte[] in) {
        update(ByteBuffer.wrap(in));
    }

    private void update(ByteBuffer in) {
        int inBytes = in.remaining();
        if (inBytes <= 0)
            return;

        if (padded)
            throw new IllegalStateException("Cannot update while padded");

        int rateBits = this.rateBits;
        if ((rateBits & 0x7) > 0) //this could be implemented but would introduce considerable performance degradation - also, it's never technically possible.
            throw new IllegalStateException("Cannot update while in bit-mode");

        long[] state = this.state;
        int rateBytes = rateBits >>> 3;

        int rateBytesWord = rateBytes & 0x7;
        if (rateBytesWord > 0) {
            //logically must have space at this point
            int c = 8 - rateBytesWord;
            if (c > inBytes)
                c = inBytes;
            int i = rateBytes >>> 3;
            long w = state[i];
            rateBytes += c;
            inBytes -= c;
            rateBytesWord <<= 3;
            c = rateBytesWord + (c << 3);
            do {
                w ^= (long) (in.get() & 0xff) << rateBytesWord;
                rateBytesWord += 8;
            } while (rateBytesWord < c);
            state[i] = w;

            if (inBytes <= 0) {
                this.rateBits = rateBytes << 3;
                return;
            }
        }

        int rateWords = rateBytes >>> 3;
        int rateSizeWords = rateSizeBits >>> 6;

        int inWords = inBytes >>> 3;
        if (inWords > 0) {
            ByteOrder order = in.order();
            try {
                in.order(ByteOrder.LITTLE_ENDIAN);
                do {
                    if (rateWords >= rateSizeWords) {
                        keccak(state);
                        rateWords = 0;
                    }
                    int c = rateSizeWords - rateWords;
                    if (c > inWords)
                        c = inWords;
                    inWords -= c;
                    c += rateWords;
                    do {
                        state[rateWords] ^= in.getLong();
                        rateWords++;
                    } while (rateWords < c);
                } while (inWords > 0);
            } finally {
                in.order(order);
            }
            inBytes &= 0x7;
            if (inBytes <= 0) {
                this.rateBits = rateWords << 6;
                return;
            }
        }

        if (rateWords >= rateSizeWords) {
            keccak(state);
            rateWords = 0;
        }
        long w = state[rateWords];
        inBytes <<= 3;
        int i = 0;
        do {
            w ^= (long) (in.get() & 0xff) << i;
            i += 8;
        } while (i < inBytes);
        state[rateWords] = w;

        this.rateBits = (rateWords << 6) | inBytes;
    }

    protected void updateBits(long in, int inBits) {
        if (inBits < 0 || inBits > 64)
            throw new IllegalArgumentException("Invalid valueBits: " + 0 + " < " + inBits + " > " + 64);

        if (inBits <= 0)
            return;

        if (padded)
            throw new IllegalStateException("Cannot update while padded");

        long[] state = this.state;
        int rateBits = this.rateBits;
        int rateBitsWord = rateBits & 0x3f;
        if (rateBitsWord > 0) {
            //logically must have space at this point
            int c = 64 - rateBitsWord;
            if (c > inBits)
                c = inBits;
            state[rateBits >>> 6] ^= (in & (-1L >>> -c)) << rateBitsWord;
            rateBits += c;
            inBits -= c;
            if (inBits <= 0) {
                this.rateBits = rateBits;
                return;
            }
            in >>>= c;
        }
        if (rateBits >= rateSizeBits) {
            Keccak1600.keccak(state);
            rateBits = 0;
        }
        state[rateBits >>> 6] ^= in & (-1L >>> -inBits);
        this.rateBits = rateBits + inBits;
    }

    public byte[] digestArray() {
        byte[] array = new byte[200];
        digest(array, 0, 200);
        return array;
    }

    private void digest(byte[] out, int offset, int length) {
        digest(ByteBuffer.wrap(out, offset, length));
    }

    private void digest(ByteBuffer out) {
        int outBytes = out.remaining();
        if (outBytes <= 0)
            return;

        long[] state = this.state;
        int rateBits = this.rateBits;
        int rateBytes;
        if (!padded) {
            pad();
            padded = true;
            rateBits = 0;
            rateBytes = 0;
        } else {
            if ((rateBits & 0x7) > 0)
                throw new IllegalStateException("Cannot digest while in bit-mode"); //this could be implemented but would introduce considerable performance degradation - also, it's never technically possible.

            rateBytes = rateBits >>> 3;
            int rateBytesWord = rateBytes & 0x7;
            if (rateBytesWord > 0) {
                int c = 8 - rateBytesWord;
                if (c > outBytes)
                    c = outBytes;
                long w = state[rateBytes >>> 3];
                outBytes -= c;
                rateBytes += c;
                rateBytesWord <<= 3;
                c = (c << 3) + rateBytesWord;
                do {
                    out.put((byte) (w >>> rateBytesWord));
                    rateBytesWord += 8;
                } while (rateBytesWord < c);
                if (outBytes <= 0) {
                    this.rateBits = rateBytes << 3;
                    return;
                }
            }
        }

        int rateSizeWords = 1600; //TODO: HACKED RATE HERE SET TO 1600
        int rateWords = rateBytes >>> 3;

        int outWords = outBytes >>> 3;
        if (outWords > 0) {
            ByteOrder order = out.order();
            try {
                out.order(ByteOrder.LITTLE_ENDIAN);
                do {
                    if (rateWords >= rateSizeWords) {
                        squeeze();
                        rateWords = 0;
                    }
                    int c = rateSizeWords - rateWords;
                    if (c > outWords)
                        c = outWords;
                    outWords -= c;
                    c += rateWords;
                    do {
                        out.putLong(state[rateWords]);
                        rateWords++;
                    } while (rateWords < c);
                } while (outWords > 0);
            } finally {
                out.order(order);
            }
            outBytes &= 0x7;
            if (outBytes <= 0) {
                this.rateBits = rateWords << 6;
                return;
            }
        }

        if (rateWords >= rateSizeWords) {
            squeeze();
            rateWords = 0;
        }
        long w = state[rateWords];
        outBytes <<= 3;
        int i = 0;
        do {
            out.put((byte) (w >>> i));
            i += 8;
        } while (i < outBytes);
        this.rateBits = (rateWords << 6) | outBytes;
    }

    protected void squeeze() {
        Keccak1600.keccak(state);
    }

    protected void pad() {
        updateBits(0x1, 1);
        if (rateBits >= rateSizeBits) {
            Keccak1600.keccak(state);
            rateBits = 0;
        }
        rateBits = rateSizeBits - 1;
        updateBits(0x1, 1);
        Keccak1600.keccak(state);
    }

    private static void keccak(long[] a) {
        //@formatter:off
        int c, i;
        long x, a_10_;
        long x0, x1, x2, x3, x4;
        long t0, t1, t2, t3, t4;
        long c0, c1, c2, c3, c4;
        long[] rc = RC;

        i = 0;
        do {
            //theta (precalculation part)
            c0 = a[0] ^ a[5 + 0] ^ a[10 + 0] ^ a[15 + 0] ^ a[20 + 0];
            c1 = a[1] ^ a[5 + 1] ^ a[10 + 1] ^ a[15 + 1] ^ a[20 + 1];
            c2 = a[2] ^ a[5 + 2] ^ a[10 + 2] ^ a[15 + 2] ^ a[20 + 2];
            c3 = a[3] ^ a[5 + 3] ^ a[10 + 3] ^ a[15 + 3] ^ a[20 + 3];
            c4 = a[4] ^ a[5 + 4] ^ a[10 + 4] ^ a[15 + 4] ^ a[20 + 4];

            t0 = (c0 << 1) ^ (c0 >>> (64 - 1)) ^ c3;
            t1 = (c1 << 1) ^ (c1 >>> (64 - 1)) ^ c4;
            t2 = (c2 << 1) ^ (c2 >>> (64 - 1)) ^ c0;
            t3 = (c3 << 1) ^ (c3 >>> (64 - 1)) ^ c1;
            t4 = (c4 << 1) ^ (c4 >>> (64 - 1)) ^ c2;

            //theta (xorring part) + rho + pi
            a[ 0] ^= t1;
            x = a[ 1] ^ t2; a_10_ = (x <<  1) | (x >>> (64 -  1));
            x = a[ 6] ^ t2; a[ 1] = (x << 44) | (x >>> (64 - 44));
            x = a[ 9] ^ t0; a[ 6] = (x << 20) | (x >>> (64 - 20));
            x = a[22] ^ t3; a[ 9] = (x << 61) | (x >>> (64 - 61));

            x = a[14] ^ t0; a[22] = (x << 39) | (x >>> (64 - 39));
            x = a[20] ^ t1; a[14] = (x << 18) | (x >>> (64 - 18));
            x = a[ 2] ^ t3; a[20] = (x << 62) | (x >>> (64 - 62));
            x = a[12] ^ t3; a[ 2] = (x << 43) | (x >>> (64 - 43));
            x = a[13] ^ t4; a[12] = (x << 25) | (x >>> (64 - 25));

            x = a[19] ^ t0; a[13] = (x <<  8) | (x >>> (64 -  8));
            x = a[23] ^ t4; a[19] = (x << 56) | (x >>> (64 - 56));
            x = a[15] ^ t1; a[23] = (x << 41) | (x >>> (64 - 41));
            x = a[ 4] ^ t0; a[15] = (x << 27) | (x >>> (64 - 27));
            x = a[24] ^ t0; a[ 4] = (x << 14) | (x >>> (64 - 14));

            x = a[21] ^ t2; a[24] = (x <<  2) | (x >>> (64 -  2));
            x = a[ 8] ^ t4; a[21] = (x << 55) | (x >>> (64 - 55));
            x = a[16] ^ t2; a[ 8] = (x << 45) | (x >>> (64 - 45));
            x = a[ 5] ^ t1; a[16] = (x << 36) | (x >>> (64 - 36));
            x = a[ 3] ^ t4; a[ 5] = (x << 28) | (x >>> (64 - 28));

            x = a[18] ^ t4; a[ 3] = (x << 21) | (x >>> (64 - 21));
            x = a[17] ^ t3; a[18] = (x << 15) | (x >>> (64 - 15));
            x = a[11] ^ t2; a[17] = (x << 10) | (x >>> (64 - 10));
            x = a[ 7] ^ t3; a[11] = (x <<  6) | (x >>> (64 -  6));
            x = a[10] ^ t1; a[ 7] = (x <<  3) | (x >>> (64 -  3));
            a[10] = a_10_;

            //chi
            c = 0;
            do {
                x0 = a[c + 0]; x1 = a[c + 1]; x2 = a[c + 2]; x3 = a[c + 3]; x4 = a[c + 4];
                a[c + 0] = x0 ^ ((~x1) & x2);
                a[c + 1] = x1 ^ ((~x2) & x3);
                a[c + 2] = x2 ^ ((~x3) & x4);
                a[c + 3] = x3 ^ ((~x4) & x0);
                a[c + 4] = x4 ^ ((~x0) & x1);

                c += 5;
            } while (c < 25);

            //iota
            a[0] ^= rc[i];

            i++;
        } while (i < 24);
        //@formatter:on
    }

    private static final long[] RC = { 0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L, 0x000000000000808BL,
            0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L, 0x000000000000008AL, 0x0000000000000088L,
            0x0000000080008009L, 0x000000008000000AL, 0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L };
}
