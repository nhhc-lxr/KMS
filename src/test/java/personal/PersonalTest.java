package personal;

import com.tencent.kona.KonaProvider;
import com.tencent.kona.crypto.CryptoUtils;
import com.tencent.kona.crypto.provider.SM4GenParameterSpec;
import com.tencent.kona.crypto.provider.SM4KeyGenerator;
import com.tencent.kona.crypto.provider.SM4KeyGeneratorTest;
import com.tencent.kona.crypto.provider.SM4ParameterGenerator;
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.sun.security.util.DerValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import security.SM2;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.CryptoUtils.toHex;
import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.util.Constants.SM4_GCM_IV_LEN;
import static com.tencent.kona.crypto.util.Constants.SM4_GCM_TAG_LEN;

public class PersonalTest {
    public static final String PROVIDER = "Kona";
    private final static String PUB_KEY
            = "041D9E2952A06C913BAD21CCC358905ADB3A8097DB6F2F87EB5F393284EC2B7208C30B4D9834D0120216D6F1A73164FDA11A87B0A053F63D992BFB0E4FC1C5D9AD";
    private final static String PRI_KEY
            = "3B03B35C2F26DBC56F6D33677F1B28AF15E45FE9B594A6426BDCAD4A69FF976B";
    private final static byte[] ID = toBytes("01234567");

    private final static byte[] MESSAGE = "测试加密用字符串数据".getBytes();

    @BeforeAll
    public static void setup() {
        Security.addProvider(new KonaProvider());
    }

    @Test
    public void testSM4KeyGen() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", PROVIDER);
        SecretKey key = keyGen.generateKey();
        System.out.println(key.getEncoded().length);

        keyGen.init(128);
        key = keyGen.generateKey();
        System.out.println(key.getEncoded().length);
    }

    @Test
    public void SM4test() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        String message;

        SecureRandom secureRandom = new SecureRandom();
        // 生成随机的密钥材料，例如128位的密钥
        byte[] keyMaterial = new byte[16]; // 16 bytes = 128 bits
        secureRandom.nextBytes(keyMaterial);// 12 bytes = 96 bits
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        System.out.println("Generated key material: " + toHex(keyMaterial));
        System.out.println("Generated GCM IV: " + toHex(iv));


        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", PROVIDER);
        SecretKey secretKey = keyGen.generateKey();
        SM4ParameterGenerator sm4ParameterGenerator = new SM4ParameterGenerator();
        sm4ParameterGenerator.


        AlgorithmParameterGenerator gcmParamGen = AlgorithmParameterGenerator.getInstance("SM4");
        gcmParamGen.init(new SM4GenParameterSpec(GCMParameterSpec.class));
        AlgorithmParameters gcmParams = gcmParamGen.generateParameters();
        byte[] encoded = gcmParams.getEncoded();
        System.out.println(toHex(gcmDecode(gcmParams.getEncoded())));


        /*Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", "Kona");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParams);
        byte[] ciphertext = cipher.doFinal(MESSAGE);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParams);
        byte[] cleartext = cipher.doFinal(ciphertext);

        System.out.println(new String(MESSAGE));
        System.out.println(new String(cleartext));*/

    }

    private byte[] gcmDecode(byte[] encoded) throws IOException {
        DerValue val = new DerValue(encoded);
        return val.data.getOctetString();
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
