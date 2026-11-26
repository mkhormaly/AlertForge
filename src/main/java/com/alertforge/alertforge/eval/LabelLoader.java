package com.alertforge.alertforge.eval;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads dataset-v1-labels.csv:
 * line_no,source_ip,label,scenario,variant,episode_id,alert_expected,expected_rule
 */
public final class LabelLoader {

    private static final int COLUMNS = 8;

    private LabelLoader() {
    }

    /** Returns the episodes keyed by their (unique) source IP. */
    public static Map<String, Episode> load(Path csv) throws IOException {
        List<String> lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        Map<String, String[]> firstRow = new LinkedHashMap<>();
        Map<String, Integer> records = new HashMap<>();

        for (int i = 1; i < lines.size(); i++) {           // line 0 is the header
            String line = lines.get(i);
            if (line.isBlank()) {
                continue;
            }
            String[] f = line.split(",", -1);
            if (f.length != COLUMNS) {
                throw new IllegalStateException("labels line " + (i + 1) + ": expected "
                        + COLUMNS + " columns, found " + f.length);
            }
            String ip = f[1];
            String[] previous = firstRow.putIfAbsent(ip, f);
            if (previous != null && !previous[5].equals(f[5])) {
                throw new IllegalStateException("labels line " + (i + 1) + ": IP " + ip
                        + " belongs to two episodes (" + previous[5] + ", " + f[5] + ")");
            }
            records.merge(ip, 1, Integer::sum);
        }

        Map<String, Episode> episodes = new LinkedHashMap<>();
        firstRow.forEach((ip, f) -> episodes.put(ip, new Episode(
                f[5], ip, f[3], f[4], "attack".equals(f[2]), f[7], records.get(ip))));
        return episodes;
    }
}
