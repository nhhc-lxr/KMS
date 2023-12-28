package config;

public class Constants {
    public static final String PUBLIC_KEY_BEGINNING = "-----BEGIN PUBLIC KEY-----\n";

    public static final String PUBLIC_KEY_ENDING = "-----END PUBLIC KEY-----";
    public static final String PRIVATE_KEY_BEGINNING = "-----BEGIN PRIVATE KEY-----\n";

    public static final String PRIVATE_KEY_ENDING = "-----END PRIVATE KEY-----";

    public static final String ALGORITHM_EC = "EC";

    public static final String ALGORITHM_SM2 = "SM2";

    // 私有构造函数，防止类被实例化
    private Constants() {
    }
}