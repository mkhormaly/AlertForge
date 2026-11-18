package com.alertforge.alertforge.model; 

import java.time.Instant;

public record Event(
        Instant timestamp,
        String source,        // e.g. "web-access"
        String sourceIp,
        String username,      // nullable: only if the log records it
        String method,
        String path,          // without query string
        String query,         // may be empty
        int statusCode,
        long bytes,
        String userAgent,
        String rawLine) {
}