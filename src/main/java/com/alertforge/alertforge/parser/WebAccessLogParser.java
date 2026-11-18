package com.alertforge.alertforge.parser;

import com.alertforge.alertforge.model.Event;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class WebAccessLogParser implements LogParser {

    // ip ident user [time] "METHOD target PROTO" status bytes "referrer" "user-agent"
    private static final Pattern COMBINED = Pattern.compile(
            "^(\\S+) \\S+ (\\S+) \\[([^\\]]+)\\] \"(\\S+) (\\S+)(?: [^\"]*)?\" (\\d{3}) (\\S+) \"([^\"]*)\" \"([^\"]*)\".*$");

    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    @Override
    public String sourceType() {
        return "web-access";
    }

    @Override
    public Optional<Event> parse(String line) {
        if (line == null || line.isBlank()) {
            return Optional.empty();
        }
        Matcher m = COMBINED.matcher(line);
        if (!m.matches()) {
            return Optional.empty();
        }
        try {
            Instant ts = ZonedDateTime.parse(m.group(3), TIME).toInstant();
            String user = "-".equals(m.group(2)) ? null : m.group(2);
            String target = m.group(5);
            int q = target.indexOf('?');
            String rawPath = q >= 0 ? target.substring(0, q) : target;
            String rawQuery = q >= 0 ? target.substring(q + 1) : "";
            // Decoded so rules see readable text; rawLine below keeps the original.
            String path = PercentDecoder.decode(rawPath, false);
            String query = PercentDecoder.decode(rawQuery, true);
            long bytes = "-".equals(m.group(7)) ? 0 : Long.parseLong(m.group(7));

            return Optional.of(new Event(ts, sourceType(), m.group(1), user,
                    m.group(4), path, query, Integer.parseInt(m.group(6)),
                    bytes, m.group(9), line));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }
}