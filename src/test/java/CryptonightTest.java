import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CryptonightTest {

    @Test
    public void cryptonightTEST(){
        String data = "This is a test";
        Cryptonight cryptonight = new Cryptonight(data);
    }

}