package com.alertforge.alertforge.eval;

import com.alertforge.alertforge.eval.EvaluationScorer.AlertRef;
import com.alertforge.alertforge.eval.EvaluationScorer.Result;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EvaluationScorerTest {

    private static Episode episode(String id, String ip, boolean attack, String rule, int records) {
        return new Episode(id, ip, attack ? "attack" : "normal", "v", attack, rule, records);
    }

    private final List<Episode> episodes = List.of(
            episode("A1", "1.1.1.1", true, "AF-001", 10),
            episode("A2", "2.2.2.2", true, "AF-003", 1),
            episode("N1", "3.3.3.3", false, "", 400),
            episode("N2", "4.4.4.4", false, "", 600));

    @Test
    void perfectDetectionScoresHundredPercent() {
        Result r = EvaluationScorer.score(episodes,
                List.of(new AlertRef("1.1.1.1", "AF-001"), new AlertRef("2.2.2.2", "AF-003")));

        assertEquals(100.0, r.overall().detectionRate());
        assertEquals(0.0, r.overall().falsePositiveRate());
        assertEquals(100.0, r.overall().precision());
        assertTrue(r.missed().isEmpty());
        assertTrue(r.falsePositives().isEmpty());
    }

    @Test
    void falsePositiveAndMissAreReportedPerRule() {
        Result r = EvaluationScorer.score(episodes, List.of(
                new AlertRef("1.1.1.1", "AF-001"),
                new AlertRef("3.3.3.3", "AF-001"),
                new AlertRef("3.3.3.3", "AF-001")));   // two alerts, still ONE false-positive episode

        assertEquals(50.0, r.forRule("AF-001").precision());
        assertEquals(1, r.forRule("AF-001").falsePositiveEpisodes());
        assertEquals(50.0, r.forRule("AF-001").falsePositiveRate());
        assertEquals(0.0, r.forRule("AF-003").detectionRate());
        assertTrue(Double.isNaN(r.forRule("AF-003").precision()));
        assertEquals(1, r.overall().detected());
        assertEquals(50.0, r.overall().precision());
        assertEquals(1, r.missed().size());
        assertTrue(r.missed().get(0).startsWith("A2") && r.missed().get(0).contains("none"));
        assertEquals(2.0, r.alertsPer1000NormalRecords(), 1e-9);   // 2 alerts / 1000 normal records
    }

    @Test
    void alertFromTheWrongRuleIsNotADetection() {
        Result r = EvaluationScorer.score(episodes, List.of(new AlertRef("2.2.2.2", "AF-001")));

        assertEquals(0, r.forRule("AF-003").detected());
        assertTrue(r.missed().stream().anyMatch(m -> m.startsWith("A2") && m.contains("AF-001")));
    }

    @Test
    void alertsFromUnknownIpsAreCountedNotScored() {
        Result r = EvaluationScorer.score(episodes, List.of(new AlertRef("9.9.9.9", "AF-002")));

        assertEquals(1, r.unmappedAlerts());
        assertEquals(1, r.alerts());
        assertEquals(0, r.alertsOnNormal());
        assertNotNull(r.forRule("AF-002"));
    }
}
