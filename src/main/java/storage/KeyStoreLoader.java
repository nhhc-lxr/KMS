package storage;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;

public class KeyStoreLoader {


    /**
     * 默认参数读取本地keystore文件
     */
    public KeyStore loadKeyStore(String keyStorePath, String keyStoreFileName, String keyStorePassword)
            throws KeyStoreException, NoSuchProviderException {
        return loadKeyStore("PKCS12", "Kona", keyStorePath, keyStoreFileName, keyStorePassword.toCharArray());

    }

    /**
     * 读取本地keystore文件
     *
     * @param keyStoreType "PKCS12"或"JKS"
     * @param provider     "KonaPKIX"
     */
    public KeyStore loadKeyStore(String keyStoreType, String provider, String keyStorePath, String keyStoreFileName,
                                 char[] keyStorePassword) throws KeyStoreException, NoSuchProviderException {
        KeyStore loadedKeyStore = KeyStore.getInstance(keyStoreType, provider);
        Path path = Paths.get(keyStorePath + keyStoreFileName);
        try (InputStream keyStoreIn = Files.newInputStream(path)) {
            loadedKeyStore.load(keyStoreIn, keyStorePassword);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return loadedKeyStore;
    }
}
