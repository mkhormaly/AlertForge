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
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(properties = "alertforge.replay.file=false")
class ThresholdDetectionTest {

    private static final Instant BASE = Instant.parse("2026-11-16T07:16:00Z");

    @Autowired
    DetectionEngine engine;

    @Autowired
    AlertRepository repository;

    @BeforeEach
    void clean() {
        repository.deleteAll();
    }

    // Each test uses its own IP: the tracker is a singleton and keeps state between tests.
    private static Event login(String ip, int second, int status) {
        return new Event(BASE.plusSeconds(second), "web-access", ip, null, "POST",
                "/rest/user/login", "", status, 26, "python-requests/2.31", "raw " + ip + " " + second);
    }

    @Test
    void fifthFailedLoginRaisesBruteForceAlert() {
        for (int s = 0; s < 4; s++) {
            engine.process(login("10.9.9.1", s, 401));
        }
        assertEquals(0, repository.count());

        engine.process(login("10.9.9.1", 4, 401));

        List<Alert> alerts = repository.findAll();
        assertEquals(1, alerts.size());
        Alert a = alerts.get(0);
        assertEquals("AF-001", a.getRuleId());
        assertEquals(Severity.HIGH, a.getSeverity());
        assertEquals("T1110.001", a.getMitreTechnique());
        assertEquals("10.9.9.1", a.getSourceIp());
        assertTrue(a.getEvidence().contains("5 matching events"), a.getEvidence());
    }

    @Test
    void successfulLoginsNeverCount() {
        for (int s = 0; s < 4; s++) {
            engine.process(login("10.9.9.2", s, 401));
        }
        for (int s = 4; s < 14; s++) {
            engine.process(login("10.9.9.2", s, 200));
        }

        assertEquals(0, repository.count());
    }

    @Test
    void failuresFromDifferentIpsAreNotPooled() {
        for (String ip : List.of("10.9.9.3", "10.9.9.4", "10.9.9.5")) {
            for (int s = 0; s < 3; s++) {
                engine.process(login(ip, s, 401));
            }
        }

        assertEquals(0, repository.count());
    }
}