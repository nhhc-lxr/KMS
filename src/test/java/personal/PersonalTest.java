package personal;

import com.tencent.kona.KonaProvider;
import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.sun.security.pkcs.PKCS8Key;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import security.SM2;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;

public class PersonalTest {
    private static final String PKCS8_V1_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgU4onpbOcBwltaLFa\n" +
                    "FwhpenJm891g0o6r+JBWnoSR6kehRANCAASfQ7HahYYaRrh0lSoU1S/5+kcEirnc\n" +
                    "HOVnVK2cTZ447fBYrjPCwiLs4KVjt27138/YYMVy+jYTXh7bPUefO+LL";

    // MIGHAgEB...
    private static final String PKCS8_V2_KEY =
            "MIGHAgEBMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgU4onpbOcBwltaLFa\n" +
                    "FwhpenJm891g0o6r+JBWnoSR6kehRANCAASfQ7HahYYaRrh0lSoU1S/5+kcEirnc\n" +
                    "HOVnVK2cTZ447fBYrjPCwiLs4KVjt27138/YYMVy+jYTXh7bPUefO+LL";

    // MIGHAgEC...
    private static final String PKCS8_V3_KEY =
            "MIGHAgECMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgU4onpbOcBwltaLFa\n" +
                    "FwhpenJm891g0o6r+JBWnoSR6kehRANCAASfQ7HahYYaRrh0lSoU1S/5+kcEirnc\n" +
                    "HOVnVK2cTZ447fBYrjPCwiLs4KVjt27138/YYMVy+jYTXh7bPUefO+LL";
    @BeforeAll
    public static void setup() {
        Security.addProvider(new KonaProvider());
    }

    @Test
    public void testKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPair keyPair = SM2.generateSM2KeyPair();
        PublicKey generatedPublicKey = keyPair.getPublic();
        PrivateKey generatedPrivateKey = keyPair.getPrivate();
        System.out.println(generatedPublicKey.getFormat());
        System.out.println(generatedPrivateKey.getFormat());
    }

    @Test
    public void testParsePKCS8V2Key() throws Exception {
        byte[] pkcs8V2Key = Base64.getMimeDecoder().decode(PKCS8_V2_KEY);
        ECPrivateKey ecPrivateKey = (ECPrivateKey) PKCS8Key.parseKey(pkcs8V2Key);

        // After encoding, the version is changed from 0x01 to 0x00.
        byte[] encoded = ecPrivateKey.getEncoded();
        byte[] pkcs8V1Key = Base64.getMimeDecoder().decode(PKCS8_V1_KEY);
        Assertions.assertArrayEquals(pkcs8V1Key, encoded);
    }
}
