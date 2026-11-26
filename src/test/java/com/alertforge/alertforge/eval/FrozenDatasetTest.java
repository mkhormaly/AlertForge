package com.alertforge.alertforge.eval;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Guards the frozen test set: if the files change, this test fails. */
class FrozenDatasetTest {

    private static final Path BASE = Path.of("data/eval/dataset-v1");

    @Test
    void shippedFilesMatchTheirManifest() throws IOException {
        DatasetIntegrity.verify(Path.of(BASE + ".log"), Path.of(BASE + "-labels.csv"),
                Path.of(BASE + "-manifest.txt"));
    }

    @Test
    void aTamperedLogIsRejected() throws IOException {
        Path tampered = Files.createTempFile("tampered", ".log");
        Files.writeString(tampered, "not the original\n");

        assertThrows(IllegalStateException.class, () -> DatasetIntegrity.verify(tampered,
                Path.of(BASE + "-labels.csv"), Path.of(BASE + "-manifest.txt")));
    }

    @Test
    void datasetHasTheDocumentedComposition() throws IOException {
        Map<String, Episode> episodes = LabelLoader.load(Path.of(BASE + "-labels.csv"));

        long attack = episodes.values().stream().filter(Episode::attack).count();
        long normalRecords = episodes.values().stream()
                .filter(e -> !e.attack()).mapToLong(Episode::records).sum();
        Set<String> expectedRules = new TreeSet<>();
        episodes.values().stream().filter(Episode::attack).forEach(e -> expectedRules.add(e.expectedRule()));

        assertEquals(370, episodes.size());
        assertEquals(180, attack);
        assertEquals(190, episodes.size() - attack);
        assertEquals(3838, normalRecords);
        assertEquals(Set.of("AF-001", "AF-002", "AF-003", "AF-004", "AF-005", "AF-006"), expectedRules);
    }
}
