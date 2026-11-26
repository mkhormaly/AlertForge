package com.alertforge.alertforge.eval;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Guards the held-out test set (dataset v2), the same way FrozenDatasetTest guards v1. */
class FrozenDatasetV2Test {

    private static final Path BASE = Path.of("data/eval/dataset-v2");

    @Test
    void shippedFilesMatchTheirManifest() throws IOException {
        DatasetIntegrity.verify(Path.of(BASE + ".log"), Path.of(BASE + "-labels.csv"),
                Path.of(BASE + "-manifest.txt"));
    }

    @Test
    void datasetHasTheDocumentedComposition() throws IOException {
        Map<String, Episode> episodes = LabelLoader.load(Path.of(BASE + "-labels.csv"));

        long attack = episodes.values().stream().filter(Episode::attack).count();
        long normalRecords = episodes.values().stream()
                .filter(e -> !e.attack()).mapToLong(Episode::records).sum();

        assertEquals(370, episodes.size());
        assertEquals(180, attack);
        assertEquals(190, episodes.size() - attack);
        assertEquals(3850, normalRecords);
    }
}
