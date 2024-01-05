package com.nhhc;

import com.tencent.kona.KonaProvider;
import com.nhhc.storage.SM2;

import java.security.*;

public class Application {


    public static void main(String[] args) throws Throwable {
        Security.addProvider(new KonaProvider());
        /**
         * -----BEGIN CERTIFICATE-----
         * MIIBOTCB36ADAgECAghk1TkJ1nBSYDAKBggqgRzPVQGDdTARMQ8wDQYDVQQDEwZl
         * Yy1zbTIwHhcNMjMxMjI2MDkzMjM1WhcNMjQwMzI1MDkzMjM1WjARMQ8wDQYDVQQD
         * EwZlYy1zbTIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAT0KM6uMJXjy9JiZbGm
         * WTDbYamwmOm2vgWYsv/bDhBECIRF/VHxvwX/lqMQEV78JxGtrMHIbGydbem3iaFM
         * HeWuoyEwHzAdBgNVHQ4EFgQUiz1HUQM3S466SRgUYD6A/tqscHAwCgYIKoEcz1UB
         * g3UDSQAwRgIhALgrrtgczeC2MJWjfJ6oI/pzEaddhUHjZqjLuYFiUnynAiEApmNU
         * C2SadhLtNEfknzNCVyyEtjEm9W2VWwlJZv3Z7vE=
         * -----END CERTIFICATE-----
         */
        /*KeyStoreLoader keyStoreLoader = new KeyStoreLoader();
        KeyStore keyStore = keyStoreLoader.loadKeyStore(ConfigLoader.KEYSTORE_PATH, ConfigLoader.KEYSTORE_File_NAME, ConfigLoader.KEYSTORE_PASSWORD);
        Key key = keyStore.getKey("ec-sm2", ConfigLoader.KEYSTORE_PASSWORD.toCharArray());
        System.out.println(key.getAlgorithm());
        System.out.println(key.getFormat());*/
        KeyPair keyPair = SM2.generateSM2KeyPair();
        PublicKey generatedPublicKey = keyPair.getPublic();
        PrivateKey generatedPrivateKey = keyPair.getPrivate();
        System.out.println(generatedPublicKey.getFormat());
        System.out.println(generatedPrivateKey.getFormat());
        //String publicKeyStr =
    }
}
