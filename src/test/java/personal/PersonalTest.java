package personal;

import com.tencent.kona.KonaProvider;
import com.tencent.kona.crypto.CryptoUtils;
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import security.SM2;

import java.security.*;
import java.security.interfaces.ECPublicKey;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

public class PersonalTest {
    public static final String PROVIDER = "Kona";
    private final static String PUB_KEY
            = "041D9E2952A06C913BAD21CCC358905ADB3A8097DB6F2F87EB5F393284EC2B7208C30B4D9834D0120216D6F1A73164FDA11A87B0A053F63D992BFB0E4FC1C5D9AD";
    private final static String PRI_KEY
            = "3B03B35C2F26DBC56F6D33677F1B28AF15E45FE9B594A6426BDCAD4A69FF976B";
    private final static byte[] ID = toBytes("01234567");

    private final static byte[] MESSAGE = toBytes(
            "4003607F75BEEE81A027BB6D265BA1499E71D5D7CD8846396E119161A57E01EEB91BF8C9FE");

    @BeforeAll
    public static void setup() {
        Security.addProvider(new KonaProvider());
    }

    @Test
    public void key2Pem() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPair keyPair = SM2.generateSM2KeyPair();
        PublicKey generatedPublicKey = keyPair.getPublic();
        PrivateKey generatedPrivateKey = keyPair.getPrivate();
        String publicPemStr = SM2.parsePublicKey2PemStr(generatedPublicKey);
        String privatePemStr = SM2.parsePrivateKey2PemStr(generatedPrivateKey);
        System.out.println("---------------");
        System.out.println("生成公钥：" + generatedPublicKey.getFormat() + "  " + generatedPublicKey.getAlgorithm());
        System.out.println(publicPemStr);
        System.out.println("生成私钥：" + generatedPrivateKey.getFormat() + "  " + generatedPrivateKey.getAlgorithm());
        System.out.println(privatePemStr);
        System.out.println("---------------");

        PublicKey loadedPublicKey = SM2.parsePemStr2PublicKey(publicPemStr);
        PrivateKey loadedPrivateKey = SM2.parsePemStr2PrivateKey(privatePemStr);
        System.out.println("生成公钥：" + loadedPublicKey.getFormat() + "  " + loadedPublicKey.getAlgorithm());
        System.out.println(SM2.parsePublicKey2PemStr(loadedPublicKey));
        System.out.println("生成私钥：" + loadedPrivateKey.getFormat() + "  " + loadedPrivateKey.getAlgorithm());
        System.out.println(SM2.parsePrivateKey2PemStr(loadedPrivateKey));
        System.out.println("---------------");
    }

    @Test
    public void testSignature() throws Exception {
        testSignature("SM2");
    }

    @Test
    public void testAlias() throws Exception {
        testSignature("SM3withSM2");
    }

    private void testSignature(String name) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance(name, PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);

        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(name, PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }
}
