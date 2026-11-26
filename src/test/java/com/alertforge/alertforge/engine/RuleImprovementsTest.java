package com.alertforge.alertforge.engine;

import com.alertforge.alertforge.model.Alert;
import com.alertforge.alertforge.model.Event;
import com.alertforge.alertforge.parser.WebAccessLogParser;
import com.alertforge.alertforge.repository.AlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Regression tests for the evaluation-driven changes to AF-003 and AF-004. */
@SpringBootTest(properties = "alertforge.replay.file=false")
class RuleImprovementsTest {

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

    private List<String> ruleIdsFor(String target) {
        String line = "10.5.5.5 - - [16/Nov/2026:10:30:00 +0300] \"GET " + target
                + " HTTP/1.1\" 200 100 \"-\" \"Mozilla/5.0\"";
        Event e = parser.parse(line).orElseThrow();
        return engine.process(e).stream().map(Alert::getRuleId).toList();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/rest/products/search?q=admin%22%20or%20%221%22%3D%221",
            "/rest/products/search?q=admin%22%20%23",
            "/rest/products/search?q=root%22)%20or%20(%221%22%3D%221%22--",
            "/rest/products/search?q=admin%22%2F*"})
    void doubleQuoteSqlInjectionIsDetected(String target) {
        assertEquals(List.of("AF-003"), ruleIdsFor(target));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/rest/products/search?q=%3Cmeta%20http-equiv%3D%22refresh%22%20content%3D%220%3Burl%3Dhttp%3A%2F%2Fevil.example%22%3E",
            "/rest/products/search?q=%22onmouseover%3Dalert(1)%2F%2F",
            "/rest/products/search?q=%27-alert(1)%2F%2F",
            "/rest/products/search?q=jAvAsCrIpT%26colon%3Balert%26lpar%3B1%26rpar%3B"})
    void additionalXssFormsAreDetected(String target) {
        assertEquals(List.of("AF-004"), ruleIdsFor(target));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/rest/products/search?q=24%22%20monitor%20stand",
            "/rest/products/search?q=alert%20(bracelet)%20medical",
            "/rest/products/search?q=confirm%20(order)%20status",
            "/rest/products/search?q=online%20store"})
    void harmlessSearchesStillRaiseNothing(String target) {
        assertEquals(List.of(), ruleIdsFor(target));
    }
}
