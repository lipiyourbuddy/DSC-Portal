package com.example.demo.util;

import java.io.File;

public class KeyToolUtil {

    public static String generateDSC(String alias, String password, String dname, String outputDir) throws Exception {
        String filename = alias + ".jks";
        File dir = new File(outputDir);
        if (!dir.exists()) dir.mkdirs();

        String keystorePath = outputDir + "/" + filename;

        String keytoolPath = "\"C:\\Program Files\\Java\\jdk-17\\bin\\keytool.exe\"";

        String command = String.format(
            "%s -genkeypair -alias \"%s\" -keyalg RSA -keystore \"%s\" -storepass \"%s\" -validity 365 -keysize 2048 -dname \"%s\" -storetype JKS",
            keytoolPath, alias, keystorePath, password, dname
        );


        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();

        return keystorePath;
    }
}
