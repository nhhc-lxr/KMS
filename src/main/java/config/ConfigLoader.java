package config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class ConfigLoader {

    public static final String KEYSTORE_PATH;
    public static final String KEYSTORE_File_NAME;
    public static final String KEYSTORE_PASSWORD;


    static {
        Properties prop = new Properties();
        try (InputStream input = ConfigLoader.class.getClassLoader().getResourceAsStream("kms.properties")) {
            prop.load(input);
            // 读取属性
            KEYSTORE_PATH = prop.getProperty("keystore.path");
            KEYSTORE_File_NAME = prop.getProperty("keystore.filename");
            KEYSTORE_PASSWORD = prop.getProperty("keystore.password");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
