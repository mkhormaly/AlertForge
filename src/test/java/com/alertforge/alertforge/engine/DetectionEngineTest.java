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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

// "false" switches off the startup replay so this test controls its own data.
@SpringBootTest(properties = "alertforge.replay.file=false")
class DetectionEngineTest {

    @Autowired
    DetectionEngine engine;

    @Autowired
    AlertRepository repository;

    @BeforeEach
    void clean() {
        repository.deleteAll();
    }

    private static Event event(String ua) {
        return new Event(Instant.parse("2026-11-16T07:17:10Z"), "web-access", "10.0.0.77", null,
                "GET", "/rest/products/search", "q=test", 200, 100, ua, "raw log line");
    }

    @Test
    void scannerUserAgentRaisesStoredAlert() {
        engine.process(event("sqlmap/1.7.2#stable (https://sqlmap.org)"));

        List<Alert> alerts = repository.findAll();
        assertEquals(1, alerts.size());
        Alert a = alerts.get(0);
        assertEquals("AF-002", a.getRuleId());
        assertEquals(Severity.MEDIUM, a.getSeverity());
        assertEquals("T1595", a.getMitreTechnique());
        assertEquals("10.0.0.77", a.getSourceIp());
        assertEquals("raw log line", a.getEvidence());
    }

    @Test
    void matchingIsCaseInsensitive() {
        engine.process(event("SQLMAP/1.7"));

        assertEquals(1, repository.count());
    }

    @Test
    void normalTrafficRaisesNoAlert() {
        engine.process(event("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));

        assertEquals(0, repository.count());
    }
}