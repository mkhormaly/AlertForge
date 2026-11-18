package com.alertforge.alertforge.ingest;

import com.alertforge.alertforge.model.Event;
import com.alertforge.alertforge.parser.LogParser;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.function.Consumer;

@Service
public class LogReplayService {

    public record ReplayResult(int totalLines, int parsed, int skipped) {}

    private final LogParser parser;

    public LogReplayService(LogParser parser) {
        this.parser = parser;
    }

    public ReplayResult replay(Path file, Consumer<Event> sink) throws IOException {
        int total = 0;
        int parsed = 0;
        // InputStreamReader replaces bad bytes instead of throwing, which matters
        // because attack logs can contain odd characters.
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(Files.newInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                total++;
                Optional<Event> event = parser.parse(line);
                if (event.isPresent()) {
                    parsed++;
                    sink.accept(event.get());
                }
            }
        }
        return new ReplayResult(total, parsed, total - parsed);
    }
}