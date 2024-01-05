package com.nhhc.storage;

import com.tencent.kona.sun.security.tools.keytool.Main;
import com.nhhc.config.ConfigLoader;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class KeyManager {
    private static final String PASSWORD = ConfigLoader.KEYSTORE_PASSWORD;


    private static final Path KEYSTORE = Paths.get(ConfigLoader.KEYSTORE_PATH + ConfigLoader.KEYSTORE_File_NAME);


    public void testGenSelfSignedCertOnPKCS12() throws Throwable {
        testGenSelfSignedCertr("PKCS12");
    }

    private void testGenSelfSignedCertr(String storeType) throws Throwable {
        genKeyPair(KEYSTORE, storeType, "ec-sm2", "EC", "curveSM2", "SM3withSM2");
        outputCert(KEYSTORE, storeType, "ec-sm2", null);
    }

    public void genKeyPair(Path keystorePath, String storeType,
                           String alias, String keyAlg, String group, String sigAlg)
            throws Throwable {
        genKeyPair(keystorePath, storeType, alias, keyAlg, group, sigAlg,
                null, null, null);
    }

    public void genKeyPair(Path keystorePath, String storeType,
                           String alias, String keyAlg, String group, String sigAlg,
                           String certPbeAlg, String keyPbeAlg, String macAlg)
            throws Throwable {
        List<String> args = new ArrayList<>();

        args.add("-v");

        args.add("-genkeypair");

        args.add("-keystore");
        args.add(keystorePath.toString());

        args.add("-storetype");
        args.add(storeType);

        args.add("-storepass");
        args.add(PASSWORD);

        args.add("-alias");
        args.add(alias);

        args.add("-keyalg");
        args.add(keyAlg);

        args.add("-keypass");
        args.add(PASSWORD);

        if (group != null) {
            args.add("-groupname");
            args.add(group);
        }

        args.add("-sigalg");
        args.add(sigAlg);

        args.add("-dname");
        args.add("CN=" + alias);

        List<String> jvmOptions = new ArrayList<>();
        if (certPbeAlg != null) {
            jvmOptions.add(
                    "-Dcom.tencent.kona.keystore.pkcs12.certPbeAlgorithm=" + certPbeAlg);
        }
        if (keyPbeAlg != null) {
            jvmOptions.add(
                    "-Dcom.tencent.kona.keystore.pkcs12.keyPbeAlgorithm=" + keyPbeAlg);
        }
        if (macAlg != null) {
            jvmOptions.add(
                    "-Dcom.tencent.kona.keystore.pkcs12.macAlgorithm=" + macAlg);
        }

        System.out.println("genKeyPair: " + String.join(" ", args));
        Main.main(args.toArray(new String[0]));
    }

    private static void outputCert(Path keystore, String storeType,
                                   String alias, Path certPath) throws Throwable {
        List<String> args = new ArrayList<>();

        args.add("-v");

        args.add("-exportcert");
        args.add("-rfc");

        args.add("-keystore");
        args.add(keystore.toString());

        args.add("-storetype");
        args.add(storeType);

        args.add("-storepass");
        args.add(PASSWORD);

        args.add("-alias");
        args.add(alias);

        if (certPath != null) {
            args.add("-file");
            args.add(certPath.toString());
        }

        System.out.println("outputCert: " + String.join(" ", args));
        Main.main(args.toArray(new String[0]));
    }
}
