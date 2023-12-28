package security;

import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.pkix.tool.KeyTool;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class SM2 {

    public KeyPair generateSM2KeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public String getSM2PublicKeyStr(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        return getSM2PrivateKeyStr(publicKey);
    }

    public String getSM2PrivateKeyStr(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public String getSM2PrivateKeyStr(KeyPair keyPair) {
        PrivateKey privateKey = keyPair.getPrivate();
        return getSM2PrivateKeyStr(privateKey);
    }

    public String getSM2PrivateKeyStr(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public PublicKey parseSM2PublicKey(String publicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        SM2PublicKeySpec sm2PublicKeySpec = new SM2PublicKeySpec(Base64.getDecoder().decode(publicKeyStr));
        return keyFactory.generatePublic(sm2PublicKeySpec);
    }

    public PrivateKey parseSM2PrivateKey(String privateKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        SM2PrivateKeySpec sm2PrivateKeySpec = new SM2PrivateKeySpec(Base64.getDecoder().decode(privateKeyStr));
        return keyFactory.generatePrivate(sm2PrivateKeySpec);
    }

    public byte[] getSM2CipherText(byte[] plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText);
    }

    public byte[] getSM2PlainText(byte[] cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        KeyTool keyTool = new KeyTool();
        return cipher.doFinal(cipherText);
    }
}
