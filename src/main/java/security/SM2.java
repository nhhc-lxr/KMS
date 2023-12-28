package security;

import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.pkix.tool.KeyTool;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class SM2 {



    public static KeyPair generateSM2KeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("curveSM2"));
        return keyPairGenerator.generateKeyPair();
    }

    public static String getSM2PublicKeyStr(PublicKey publicKey) {
        return Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
    }

    public static String getSM2PrivateKeyStr(PrivateKey privateKey) {
        return Base64.getMimeEncoder().encodeToString(privateKey.getEncoded());
    }

    public static PublicKey parseSM2PublicKey(String publicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        SM2PublicKeySpec sm2PublicKeySpec = new SM2PublicKeySpec(Base64.getDecoder().decode(publicKeyStr));
        return keyFactory.generatePublic(sm2PublicKeySpec);
    }

    public static PrivateKey parseSM2PrivateKey(String privateKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        SM2PrivateKeySpec sm2PrivateKeySpec = new SM2PrivateKeySpec(Base64.getDecoder().decode(privateKeyStr));
        return keyFactory.generatePrivate(sm2PrivateKeySpec);
    }

    public static byte[] getSM2CipherText(byte[] plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText);
    }

    public static byte[] getSM2PlainText(byte[] cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        KeyTool keyTool = new KeyTool();
        return cipher.doFinal(cipherText);
    }
}
