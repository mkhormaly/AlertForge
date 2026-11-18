package com.alertforge.alertforge.ingest;

import com.alertforge.alertforge.model.Event;
import com.alertforge.alertforge.parser.WebAccessLogParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LogReplayServiceTest {

    @TempDir
    Path dir;

    @Test
    void countsParsedAndSkippedLines() throws IOException {
        String good1 = "192.168.1.10 - - [16/Nov/2026:10:15:32 +0300] \"GET / HTTP/1.1\" 200 1950 \"-\" \"Mozilla/5.0\"";
        String good2 = "10.0.0.99 - - [16/Nov/2026:10:16:01 +0300] \"POST /rest/user/login HTTP/1.1\" 401 26 \"-\" \"curl/8.0\"";
        Path file = dir.resolve("test.log");
        Files.writeString(file, good1 + "\ngarbage line\n" + good2 + "\n");

        LogReplayService service = new LogReplayService(new WebAccessLogParser());
        List<Event> received = new ArrayList<>();
        var result = service.replay(file, received::add);

        assertEquals(3, result.totalLines());
        assertEquals(2, result.parsed());
        assertEquals(1, result.skipped());
        assertEquals(2, received.size());
    }
}