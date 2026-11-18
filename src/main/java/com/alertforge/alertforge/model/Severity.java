package com.alertforge.alertforge.model;

import java.util.Locale;
import java.util.Optional;

public enum Severity {
    LOW, MEDIUM, HIGH, CRITICAL;

    public static Optional<Severity> parse(String text) {
        if (text == null) {
            return Optional.empty();
        }
        try {
            // Locale.ROOT matters: on a Turkish-locale machine "critical".toUpperCase()
            // becomes "CRİTİCAL" (dotted İ) and would not match the enum.
            return Optional.of(valueOf(text.trim().toUpperCase(Locale.ROOT)));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}