package com.alertforge.alertforge.engine;

import com.alertforge.alertforge.model.Alert;
import com.alertforge.alertforge.model.Event;
import com.alertforge.alertforge.repository.AlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(properties = "alertforge.replay.file=false")
class ScannerRuleMappingTest {

    @Autowired
    DetectionEngine engine;

    @Autowired
    AlertRepository repository;

    @BeforeEach
    void clean() {
        repository.deleteAll();
    }

    private List<Alert> run(String userAgent) {
        Event e = new Event(Instant.parse("2026-11-16T07:21:30Z"), "web-access", "10.6.6.6", null,
                "GET", "/admin", "", 404, 150, userAgent, "raw line");
        return engine.process(e);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None)",
            "sqlmap/1.7.2#stable (https://sqlmap.org)",
            "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"})
    void vulnerabilityScannersMapToT1595_002(String ua) {
        List<Alert> alerts = run(ua);

        assertEquals(1, alerts.size());
        assertEquals("AF-002", alerts.get(0).getRuleId());
        assertEquals("T1595.002", alerts.get(0).getMitreTechnique());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "gobuster/3.6",
            "Fuzz Faster U Fool v2.1.0",
            "feroxbuster/2.10.0",
            "Wfuzz/3.1.0",
            "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)"})
    void directoryScannersMapToT1595_003(String ua) {
        List<Alert> alerts = run(ua);

        assertEquals(1, alerts.size());
        assertEquals("AF-006", alerts.get(0).getRuleId());
        assertEquals("T1595.003", alerts.get(0).getMitreTechnique());
    }

    @Test
    void ordinaryBrowserRaisesNoScannerAlert() {
        assertEquals(0, run("Mozilla/5.0 (Windows NT 10.0; Win64; x64)").size());
    }
}