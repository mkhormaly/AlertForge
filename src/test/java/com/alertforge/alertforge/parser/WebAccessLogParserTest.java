package com.alertforge.alertforge.parser;

import com.alertforge.alertforge.model.Event;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class WebAccessLogParserTest {

    private final WebAccessLogParser parser = new WebAccessLogParser();

    @Test
    void parsesFailedLogin() {
        String line = "192.168.1.10 - - [16/Nov/2026:10:15:32 +0300] "
                + "\"POST /rest/user/login HTTP/1.1\" 401 26 \"-\" \"Mozilla/5.0\"";
        Event e = parser.parse(line).orElseThrow();

        assertEquals("192.168.1.10", e.sourceIp());
        assertEquals("POST", e.method());
        assertEquals("/rest/user/login", e.path());
        assertEquals("", e.query());
        assertEquals(401, e.statusCode());
        assertEquals(26, e.bytes());
        assertEquals("Mozilla/5.0", e.userAgent());
        assertNull(e.username());
        assertEquals(Instant.parse("2026-11-16T07:15:32Z"), e.timestamp());
    }

    @Test
    void splitsPathAndQuery() {
        String line = "10.0.0.5 - - [16/Nov/2026:10:16:00 +0300] "
                + "\"GET /rest/products/search?q=apple HTTP/1.1\" 200 - \"-\" \"curl/8.0\"";
        Event e = parser.parse(line).orElseThrow();

        assertEquals("/rest/products/search", e.path());
        assertEquals("q=apple", e.query());
        assertEquals(0, e.bytes());
    }

    @Test
    void malformedLineGivesEmpty() {
        assertEquals(Optional.empty(), parser.parse("this is not a log line"));
        assertEquals(Optional.empty(), parser.parse(""));
        assertEquals(Optional.empty(), parser.parse(null));
    }

        @Test
    void decodesPercentEncodedQueryButKeepsRawLine() {
        String line = "10.0.0.5 - - [16/Nov/2026:10:16:00 +0300] "
                + "\"GET /rest/products/search?q=1%27%20OR%201%3D1-- HTTP/1.1\" 200 0 \"-\" \"curl/8.0\"";
        Event e = parser.parse(line).orElseThrow();

        assertEquals("q=1' OR 1=1--", e.query());
        assertEquals(line, e.rawLine());
    }

    @Test
    void decodesDoubleEncodedInput() {
        String line = "10.0.0.5 - - [16/Nov/2026:10:16:00 +0300] "
                + "\"GET /a?q=%2527 HTTP/1.1\" 200 0 \"-\" \"curl/8.0\"";

        assertEquals("q='", parser.parse(line).orElseThrow().query());
    }

    @Test
    void keepsMalformedPercentSequencesWithoutFailing() {
        String line = "10.0.0.5 - - [16/Nov/2026:10:16:00 +0300] "
                + "\"GET /a?q=50%zz HTTP/1.1\" 200 0 \"-\" \"curl/8.0\"";

        assertEquals("q=50%zz", parser.parse(line).orElseThrow().query());
    }

    @Test
    void plusIsSpaceInQueryButNotInPath() {
        String line = "10.0.0.5 - - [16/Nov/2026:10:16:00 +0300] "
                + "\"GET /a+b?q=apple+juice HTTP/1.1\" 200 0 \"-\" \"curl/8.0\"";
        Event e = parser.parse(line).orElseThrow();

        assertEquals("/a+b", e.path());
        assertEquals("q=apple juice", e.query());
    }
}