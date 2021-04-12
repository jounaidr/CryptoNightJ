import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CryptonightTest {

    List<String> inputData = Arrays
            .asList("This is a test",
                    "",
                    "de omnibus dubitandum",
                    "caveat emptor",
                    "ex nihilo nihil fit");

    List<String> validHashes = Arrays
            .asList("a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605",
                    "eb14e8a833fac6fe9a43b57b336789c46ffe93f2868452240720607b14387e11",
                    "2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5",
                    "bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87",
                    "b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05");

    @Test
    public void TestHashCorrect(){
        for (int i = 0; i < inputData.size(); i++) {
            Cryptonight cryptonight = new Cryptonight(inputData.get(i));
            assertEquals(validHashes.get(i),new String(Hex.encode(cryptonight.returnHash())));
        }
    }

    @Test
    public void TestHashSpeed(){
        long totalTime = 0;

        for (String inputDatum : inputData) {
            for (int x = 0; x < 1000; x++) { //calculate each hash 1000 times each (5000 in total)
                long startTime = System.currentTimeMillis(); //start timer

                Cryptonight cryptonight = new Cryptonight(inputDatum); //calculate hash

                long endTime = System.currentTimeMillis();

                totalTime = totalTime + (endTime - startTime); //end timer
            }
        }

        float hashRate = (5000 / ((float)totalTime / 1000));

        System.out.println("Total time taken after 5000 hashes for JNI com.jounaidr.JCryptoNight.Cryptonight is: " + (totalTime) + " milliseconds");
        System.out.println("Hash rate for JNI com.jounaidr.JCryptoNight.Cryptonight is: " + (hashRate) + "H/s");
    }

}