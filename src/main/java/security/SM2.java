package security;

import com.sun.deploy.util.StringUtils;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static config.Constants.*;

public class SM2 {


    /**
     * 生成一对SM2密钥对
     * KeyPairGenerator.getInstance(ALGORITHM_XX)参数决定密钥格式
     * "EC"时生成的密钥对格式为：
     * 私钥：PKCS#8，公钥：X.509
     * "SM2"时生成的密钥对格式为：
     * 私钥：RAW，公钥：RAW
     *
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateSM2KeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_EC);
        keyPairGenerator.initialize(new ECGenParameterSpec("curveSM2"));
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 将密钥转为PEM字符串(不含头尾)
     *
     * @param key
     * @return
     */
    public static String parseKey2PemStrWithoutBE(Key key) {
        return Base64.getMimeEncoder().encodeToString(key.getEncoded());
    }

    /**
     * 将公钥对象转为PEM字符串
     * @param key
     * @return
     */
    public static String parsePublicKey2PemStr(Key key) {
        String str = parseKey2PemStrWithoutBE(key);
        return PUBLIC_KEY_BEGINNING + str + "\n" + PUBLIC_KEY_ENDING;
    }

    /**
     * 将私钥对象转为PEM字符串
     * @param key
     * @return
     */
    public static String parsePrivateKey2PemStr(Key key) {
        String str = parseKey2PemStrWithoutBE(key);
        return PRIVATE_KEY_BEGINNING + str + "\n" + PRIVATE_KEY_ENDING;
    }

    /**
     * 根据PEM字符串获取公钥对象
     * @param publicKeyStr
     * @return
     */
    public static PublicKey parsePemStr2PublicKey(String publicKeyStr) {
        try {
            publicKeyStr = publicKeyStr.replace(PUBLIC_KEY_BEGINNING, "").replace(PUBLIC_KEY_ENDING, "");
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec sm2PublicKeySpec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(publicKeyStr));
            return keyFactory.generatePublic(sm2PublicKeySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey parsePemStr2PrivateKey(String privateKeyStr) {
        try {
            privateKeyStr = privateKeyStr.replace(PRIVATE_KEY_BEGINNING, "").replace(PRIVATE_KEY_ENDING, "");
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec sm2PrivateKeySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(privateKeyStr));
            return keyFactory.generatePrivate(sm2PrivateKeySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static byte[] getSM2CipherText(byte[] plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("EC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText);
    }

    public static byte[] getSM2PlainText(byte[] cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("EC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherText);
    }
}
