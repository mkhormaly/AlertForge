package com.alertforge.alertforge.web;

import com.alertforge.alertforge.model.Alert;
import com.alertforge.alertforge.model.Severity;
import com.alertforge.alertforge.repository.AlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(properties = "alertforge.replay.file=false")
class AlertControllerTest {

    @Autowired
    AlertController controller;

    @Autowired
    AlertRepository repository;

    private static Alert alert(String ruleId, Severity severity, String eventTime) {
        return new Alert(ruleId, "Title " + ruleId, severity, "T1110.001", "Credential Access",
                "10.0.0.1", Instant.parse(eventTime), Instant.now(), "raw " + ruleId);
    }

    @BeforeEach
    void seed() {
        repository.deleteAll();
        repository.save(alert("R-OLD", Severity.MEDIUM, "2026-11-16T07:00:00Z"));
        repository.save(alert("R-NEW", Severity.HIGH, "2026-11-16T08:00:00Z"));
        repository.save(alert("R-MID", Severity.MEDIUM, "2026-11-16T07:30:00Z"));
    }

    @Test
    void listsNewestEventFirst() {
        List<AlertResponse> all = controller.list(null);

        assertEquals(List.of("R-NEW", "R-MID", "R-OLD"),
                all.stream().map(AlertResponse::ruleId).toList());
        assertEquals("2026-11-16T08:00:00Z", all.get(0).eventTimestamp());
    }

    @Test
    void filtersBySeverityCaseInsensitively() {
        List<AlertResponse> medium = controller.list("medium");

        assertEquals(List.of("R-MID", "R-OLD"),
                medium.stream().map(AlertResponse::ruleId).toList());
        assertEquals(1, controller.list("HIGH").size());
        assertEquals(0, controller.list("CRITICAL").size());
    }

    @Test
    void blankSeverityMeansNoFilter() {
        assertEquals(3, controller.list("  ").size());
    }

    @Test
    void unknownSeverityIsRejectedWith400() {
        ResponseStatusException ex =
                assertThrows(ResponseStatusException.class, () -> controller.list("urgent"));

        assertEquals(400, ex.getStatusCode().value());
    }
}