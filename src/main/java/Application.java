import com.tencent.kona.KonaProvider;
import config.ConfigLoader;
import storage.KeyManager;
import storage.KeyStoreLoader;

import java.security.Key;
import java.security.KeyStore;
import java.security.Security;

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
        KeyStoreLoader keyStoreLoader = new KeyStoreLoader();
        KeyStore keyStore = keyStoreLoader.loadKeyStore(ConfigLoader.KEYSTORE_PATH, ConfigLoader.KEYSTORE_File_NAME, ConfigLoader.KEYSTORE_PASSWORD);
        Key key = keyStore.getKey("ec-sm2", ConfigLoader.KEYSTORE_PASSWORD.toCharArray());
        System.out.println(key.getAlgorithm());
        System.out.println(key.getFormat());
    }
}
