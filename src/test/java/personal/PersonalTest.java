package personal;

import com.tencent.kona.KonaProvider;
import com.tencent.kona.pkix.PKIXUtils;
import com.tencent.kona.sun.security.util.DerValue;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.nhhc.storage.SM2;
import com.nhhc.storage.KeyStoreLoader;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Enumeration;

import static com.tencent.kona.crypto.CryptoUtils.toHex;
import static com.nhhc.config.Constants.*;

public class PersonalTest {

    private final static byte[] MESSAGE = "测试加密用字符串数据".getBytes();

    private final static String TRUSTSTORE = "src/test/resources/personal/truststore.p12";
    private final static String TRUSTSTOREPASSWORD = "truststorepass";
    private final static String KEYSTORE = "src/test/resources/personal/keystore.p12";
    private final static String KEYSTOREPASSWORD = "keystorepass";

    @BeforeAll
    public static void setup() {
        Security.addProvider(new KonaProvider());
    }


    @Test
    public void tlcpDemo() throws Exception {
        CloseableHttpClient client = createClient();
        // Access Servlet /hello over HTTPS scheme.
        //HttpGet getMethod = new HttpGet(String.format("https://localhost:%d/test/jetty", 8443));
        HttpGet getMethod = new HttpGet(String.format("https://localhost:%d/CARootCert/getCARootCert", 8443));

        CloseableHttpResponse response = client.execute(getMethod);
        client.close();

        //System.out.println(response.toString());

        HttpEntity entity = response.getEntity();
        if (entity != null) {
            String responseString = EntityUtils.toString(entity);
            System.out.println(responseString); // 输出服务器返回的字符串
        }
        response.close();
    }


    // Create Apache HttpClient client, which supports TLCP connection.
    private static CloseableHttpClient createClient() throws Exception {
        SSLContext context = createContext();

        SSLConnectionSocketFactory socketFactory
                = new SSLConnectionSocketFactory(context);
        return HttpClients.custom()
                .setSSLSocketFactory(socketFactory).build();
    }

    private static SSLContext createContext() throws Exception {
        // Load trust store
        KeyStore trustStore = KeyStore.getInstance("PKCS12", "Kona");
        try (FileInputStream keyStoreIn = new FileInputStream(TRUSTSTORE)) {
            trustStore.load(keyStoreIn, TRUSTSTOREPASSWORD.toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "Kona");
        tmf.init(trustStore);

        // Load key store
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "Kona");
        try (FileInputStream keyStoreIn = new FileInputStream(KEYSTORE)) {
            keyStore.load(keyStoreIn, KEYSTOREPASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509", "Kona");
        kmf.init(keyStore, KEYSTOREPASSWORD.toCharArray());

        SSLContext context = SSLContext.getInstance("TLCP", "Kona");
        KeyManager[] keyManagers = {};
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return context;
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
        System.out.println("----------" + toHex(cipherGeneratedIV));
        System.out.println("----------" + toHex(gcmDecodeIV(parameters.getEncoded())));

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
        KeyStore keyStore = KeyStoreLoader.loadKeyStore("src/test/resources/personal/", "keystore.p12", "keystorepass");
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias: " + alias);
        }

        // 导出证书
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate("ee-enc");
        System.out.println(PKIXUtils.isEncCert(certificate));
        System.out.println(Arrays.toString(certificate.getKeyUsage()));
        /*byte[] certBytes = certificate.getEncoded();
        String encodedCert = Base64.getMimeEncoder().encodeToString(certBytes);

        try (FileOutputStream fos = new FileOutputStream("src/test/resources/personal/certificate.pem")) {
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(encodedCert.getBytes());
            fos.write("\n-----END CERTIFICATE-----".getBytes());
        } catch (IOException e) {
            // 处理文件操作异常
            e.printStackTrace();
        }*/
    }
}
