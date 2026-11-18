package com.alertforge.alertforge.parser;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** Lenient percent-decoder: never throws, keeps invalid %-sequences, undoes double encoding. */
public final class PercentDecoder {

    private static final int MAX_PASSES = 2;

    private PercentDecoder() {}

    public static String decode(String input, boolean plusAsSpace) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        String current = input;
        for (int pass = 0; pass < MAX_PASSES; pass++) {
            String next = decodeOnce(current, plusAsSpace);
            if (next.equals(current)) {
                break;
            }
            current = next;
        }
        return current;
    }

    private static String decodeOnce(String s, boolean plusAsSpace) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); ) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    out.write((hi << 4) | lo);
                    i += 3;
                    continue;
                }
            }
            if (c == '+' && plusAsSpace) {
                out.write(' ');
                i++;
                continue;
            }
            int cp = s.codePointAt(i);
            byte[] bytes = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
            out.write(bytes, 0, bytes.length);
            i += Character.charCount(cp);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }
}