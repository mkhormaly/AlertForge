package com.alertforge.alertforge.engine;

import com.alertforge.alertforge.model.Alert;
import com.alertforge.alertforge.model.Event;
import com.alertforge.alertforge.parser.WebAccessLogParser;
import com.alertforge.alertforge.repository.AlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(properties = "alertforge.replay.file=false")
class WebAttackDetectionTest {

    @Autowired
    DetectionEngine engine;

    @Autowired
    WebAccessLogParser parser;

    @Autowired
    AlertRepository repository;

    @BeforeEach
    void clean() {
        repository.deleteAll();
    }

    private static String line(String target) {
        return "10.8.8.8 - - [16/Nov/2026:10:30:00 +0300] \"GET " + target
                + " HTTP/1.1\" 200 100 \"-\" \"Mozilla/5.0\"";
    }

    private List<String> ruleIdsFor(String target) {
        Event e = parser.parse(line(target)).orElseThrow();
        return engine.process(e).stream().map(Alert::getRuleId).toList();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/rest/products/search?q=%27%20OR%201%3D1--",
            "/rest/products/search?q=x%27%20UNION%20SELECT%20email%2Cpassword%20FROM%20Users--",
            "/rest/products/search?q=x%27%2F**%2FUNION%2F**%2FSELECT%2F**%2F1",
            "/rest/products/search?q=1%27%3BSELECT%20SLEEP(5)--",
            "/rest/products/search?q=%27%20AND%20%27a%27%3D%27a",
            "/rest/products/search?q=a%27%20--%20",
            "/rest/products/search?q=%2527%2520OR%25201%253D1--"
    })
    void sqlInjectionIsDetected(String target) {
        assertEquals(List.of("AF-003"), ruleIdsFor(target));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "/rest/products/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
            "/rest/products/search?q=javascript%3Aalert(1)",
            "/rest/products/search?q=%3Csvg%20onload%3Dalert(1)%3E",
            "/rest/products/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"
    })
    void xssIsDetected(String target) {
        assertEquals(List.of("AF-004"), ruleIdsFor(target));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/rest/products/search?q=apple%20juice",
            "/rest/products/search?q=caf%C3%A9%20au%20lait",
            "/rest/products/search?q=salt+and+pepper",
            "/rest/products/search?q=rock%20%26%20roll",
            "/rest/products/search?q=50%25%20off",
            "/api/Products/12",
            "/rest/user/whoami"
    })
    void normalRequestsRaiseNoAlert(String target) {
        assertEquals(List.of(), ruleIdsFor(target));
        assertEquals(0, repository.count());
    }

    @Test
    void alertEvidenceKeepsTheOriginalEncodedLine() {
        String raw = line("/rest/products/search?q=%27%20OR%201%3D1--");
        engine.process(parser.parse(raw).orElseThrow());

        assertEquals(raw, repository.findAll().get(0).getEvidence());
    }
}