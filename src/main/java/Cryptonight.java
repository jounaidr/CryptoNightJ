public class Cryptonight {
    private byte[] out;

    public Cryptonight(String data) {
        out = keccak(data);

//        //Make key
//        byte[] key = new byte[32];
//        System.arraycopy(out, 0, key, 0, 32);
//
//        //Make blocks
//        byte[][] blocks = new byte[8][];
//        for (int i = 0; i < 8; ++i)
//            System.arraycopy(out, 64 + 16 * i, blocks[i], 0, 16);
//
//        byte[][] keys = new byte[11][];
//        keys[0]=key;
//        for (int i = 0; i < 10; ++i) {
//            keys[i+1]=new byte[32];
//            Rijndael.expandKey(keys[i], keys[i+1], 0, 32, 32);
//        }
//
//        //byte[] pad = new byte[2097152];
//
//        //Encrypt blocks
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

    private byte[] keccak(String data){
        //Keccak1600 keccakHasher = new Keccak1600(data); //TODO: update keccak1600 class to take in data as digestSize will always be 512
        //byte[] out = keccakHasher.digestArray(200);
        //return out;
        return null;
    }
}
