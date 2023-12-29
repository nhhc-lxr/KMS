package personal;

import com.tencent.kona.KonaProvider;
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.pkix.PKIXInsts;
import com.tencent.kona.sun.security.util.DerValue;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import security.SM2;
import storage.KeyStoreLoader;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Properties;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.CryptoUtils.toHex;
import static config.Constants.*;

public class PersonalTest {

    private final static byte[] MESSAGE = "测试加密用字符串数据".getBytes();

    @BeforeAll
    public static void setup() {
        Security.addProvider(new KonaProvider());
    }

    @Test
    public void testSM4KeyGen() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_SM4, PROVIDER);
        SecretKey key = keyGen.generateKey();
        System.out.println(key.getEncoded().length);

        keyGen.init(128);
        key = keyGen.generateKey();
        System.out.println(key.getEncoded().length);
    }

    @Test
    public void SM4test() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidParameterSpecException {

        SecureRandom secureRandom = new SecureRandom();
        // 生成随机的密钥材料，例如128位的密钥
        byte[] keyMaterial = new byte[16]; // 16 bytes = 128 bits
        secureRandom.nextBytes(keyMaterial);// 12 bytes = 96 bits
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        System.out.println("Generated key material: " + toHex(keyMaterial));
        System.out.println("Generated GCM IV: " + toHex(iv));


        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_SM4, PROVIDER);
        SecretKey secretKey = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance(TRANSFORMATION_SM4_GCM, PROVIDER);
        //生成IV
        AlgorithmParameters parameters = cipher.getParameters();
        GCMParameterSpec parameterSpec = parameters.getParameterSpec(GCMParameterSpec.class);
        byte[] cipherGeneratedIV = parameterSpec.getIV();
        System.out.println("----------"+toHex(cipherGeneratedIV));
        System.out.println("----------"+toHex(gcmDecodeIV(parameters.getEncoded())));

        //使用SM4密钥和IV加密
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameters);
        byte[] ciphertext = cipher.doFinal(MESSAGE);
        //解密
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameters);
        byte[] cleartext = cipher.doFinal(ciphertext);

        System.out.println(new String(MESSAGE));
        System.out.println(new String(cleartext));

    }

    private byte[] gcmDecodeIV(byte[] encoded) throws IOException {
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
    public void outPutCert() throws KeyStoreException, NoSuchProviderException, CertificateEncodingException {
        // 读取 KeyStore 文件
        KeyStore keyStore = KeyStoreLoader.loadKeyStore("src/test/resources/personal/", "truststore.p12", "truststorepass");
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias: " + alias);
        }

        // 导出证书
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate("ca");
        byte[] certBytes = certificate.getEncoded();
        String encodedCert = Base64.getMimeEncoder().encodeToString(certBytes);

        try (FileOutputStream fos = new FileOutputStream("src/test/resources/personal/certificate.pem")) {
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(encodedCert.getBytes());
            fos.write("\n-----END CERTIFICATE-----".getBytes());
        } catch (IOException e) {
            // 处理文件操作异常
            e.printStackTrace();
        }
    }
}
