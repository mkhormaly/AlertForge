package com.alertforge.alertforge.engine;

import com.alertforge.alertforge.model.Alert;
import com.alertforge.alertforge.model.Event;
import com.alertforge.alertforge.model.Severity;
import com.alertforge.alertforge.repository.AlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(properties = "alertforge.replay.file=false")
class EnumerationDetectionTest {

    private static final Instant BASE = Instant.parse("2026-11-16T07:20:00Z");

    @Autowired
    DetectionEngine engine;

    @Autowired
    AlertRepository repository;

    @BeforeEach
    void clean() {
        repository.deleteAll();
    }

    // Each test uses its own IP: the tracker is a singleton and keeps state between tests.
    private static Event get(String ip, int second, String path) {
        return new Event(BASE.plusSeconds(second), "web-access", ip, null, "GET",
                path, "", 200, 512, "python-requests/2.31", "raw " + ip + " " + path);
    }

    @Test
    void fifteenSequentialIdRequestsRaiseLowSeverityAlert() {
        for (int i = 0; i < 14; i++) {
            engine.process(get("10.7.7.1", i, "/api/Products/" + (i + 1)));
        }
        assertEquals(0, repository.count());

        engine.process(get("10.7.7.1", 14, "/api/Products/15"));

        assertEquals(1, repository.count());
        Alert a = repository.findAll().get(0);
        assertEquals("AF-005", a.getRuleId());
        assertEquals(Severity.LOW, a.getSeverity());
        assertEquals("T1190", a.getMitreTechnique());
        assertEquals("10.7.7.1", a.getSourceIp());
    }

    @Test
    void slowBrowsingDoesNotAlert() {
        for (int i = 0; i < 20; i++) {
            engine.process(get("10.7.7.2", i * 20, "/api/Products/" + (i + 1)));
        }

        assertEquals(0, repository.count());
    }

    @Test
    void pathsWithoutNumericIdAreIgnored() {
        for (int i = 0; i < 30; i++) {
            engine.process(get("10.7.7.3", i, "/rest/products/search"));
        }

        assertEquals(0, repository.count());
    }

    @Test
    void sustainedEnumerationRaisesOnlyOneAlertPerWindow() {
        for (int i = 0; i < 40; i++) {
            engine.process(get("10.7.7.4", i, "/api/Users/" + (i + 1)));
        }

        assertEquals(1, repository.count());
    }
}