package com.alertforge.alertforge.rules;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RuleLoaderTest {

    @TempDir
    Path dir;

    private final RuleLoader loader = new RuleLoader(new RuleValidator());

    private static final String VALID_MATCH = """
            id: T-001
            title: Test match rule
            severity: Medium
            type: match
            mitre:
              technique: T1595
            conditions:
              - field: userAgent
                operator: contains
                values: [nikto, sqlmap]
            """;

    @Test
    void loadsValidMatchRule() throws IOException {
        Path f = dir.resolve("a.yml");
        Files.writeString(f, VALID_MATCH);

        Rule r = loader.loadFile(f);

        assertEquals("T-001", r.getId());
        assertEquals("match", r.getType());
        assertEquals("T1595", r.getMitre().getTechnique());
        assertEquals(1, r.getConditions().size());
        assertEquals(List.of("nikto", "sqlmap"), r.getConditions().get(0).getValues());
    }

    @Test
    void loadsThresholdRule() throws IOException {
        Path f = dir.resolve("b.yml");
        Files.writeString(f, """
                id: T-002
                title: Test threshold rule
                severity: high
                type: threshold
                mitre:
                  technique: T1110.001
                conditions:
                  - field: statusCode
                    operator: equals
                    values: ["401"]
                threshold:
                  count: 5
                  windowSeconds: 60
                  groupBy: sourceIp
                """);

        Rule r = loader.loadFile(f);

        assertEquals(5, r.getThreshold().getCount());
        assertEquals(60, r.getThreshold().getWindowSeconds());
        assertEquals("sourceIp", r.getThreshold().getGroupBy());
    }

    @Test
    void rejectsBadSeverityAndUnknownField() throws IOException {
        Path f = dir.resolve("c.yml");
        Files.writeString(f, VALID_MATCH
                .replace("severity: Medium", "severity: urgent")
                .replace("field: userAgent", "field: nonsense"));

        RuleLoadException ex = assertThrows(RuleLoadException.class, () -> loader.loadFile(f));

        assertTrue(ex.getMessage().contains("severity"), ex.getMessage());
        assertTrue(ex.getMessage().contains("nonsense"), ex.getMessage());
    }

    @Test
    void rejectsThresholdRuleWithoutThresholdBlock() throws IOException {
        Path f = dir.resolve("d.yml");
        Files.writeString(f, VALID_MATCH.replace("type: match", "type: threshold"));

        RuleLoadException ex = assertThrows(RuleLoadException.class, () -> loader.loadFile(f));

        assertTrue(ex.getMessage().contains("threshold"), ex.getMessage());
    }

    @Test
    void rejectsUnknownYamlKey() throws IOException {
        Path f = dir.resolve("e.yml");
        Files.writeString(f, VALID_MATCH + "severty: high\n");

        assertThrows(RuleLoadException.class, () -> loader.loadFile(f));
    }

    @Test
    void rejectsDuplicateIds() throws IOException {
        Files.writeString(dir.resolve("one.yml"), VALID_MATCH);
        Files.writeString(dir.resolve("two.yml"), VALID_MATCH);

        RuleLoadException ex = assertThrows(RuleLoadException.class, () -> loader.loadAll(dir));

        assertTrue(ex.getMessage().contains("duplicate"), ex.getMessage());
    }

    @Test
    void shippedRulesAreValid() throws IOException {
        List<Rule> rules = loader.loadAll(Path.of("rules"));

        assertEquals(6, rules.size());
    }
}