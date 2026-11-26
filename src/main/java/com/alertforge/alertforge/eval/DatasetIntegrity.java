package com.alertforge.alertforge.eval;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

/** Proves that the frozen dataset was not changed after the manifest was written. */
public final class DatasetIntegrity {

    private DatasetIntegrity() {
    }

    public static void verify(Path logFile, Path labelsFile, Path manifestFile) throws IOException {
        Map<String, String> manifest = new HashMap<>();
        for (String line : Files.readAllLines(manifestFile)) {
            int eq = line.indexOf('=');
            if (eq > 0) {
                manifest.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
        }
        check("log", sha256(logFile), manifest.get("log_sha256"));
        check("labels", sha256(labelsFile), manifest.get("labels_sha256"));
    }

    private static void check(String what, String actual, String expected) {
        if (!actual.equals(expected)) {
            throw new IllegalStateException("Dataset " + what + " file differs from its manifest "
                    + "(expected " + expected + ", found " + actual + "). The test set is frozen: "
                    + "restore the original file instead of editing it.");
        }
    }

    /** SHA-256 over the file with carriage returns removed, so Windows/Git line-ending changes do not matter. */
    static String sha256(Path file) throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte b : bytes) {
                if (b != '\r') {
                    digest.update(b);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
