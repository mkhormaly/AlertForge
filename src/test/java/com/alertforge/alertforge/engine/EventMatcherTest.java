package com.alertforge.alertforge.engine;

import com.alertforge.alertforge.model.Event;
import com.alertforge.alertforge.rules.Rule;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EventMatcherTest {

    private final EventMatcher matcher = new EventMatcher();

    private static Rule.Condition cond(String field, String operator, String... values) {
        Rule.Condition c = new Rule.Condition();
        c.setField(field);
        c.setOperator(operator);
        c.setValues(List.of(values));
        return c;
    }

    private static Rule rule(Rule.Condition... conditions) {
        Rule r = new Rule();
        r.setConditions(List.of(conditions));
        return r;
    }

    private static Event event(String user, String method, String path, int status, String ua) {
        return new Event(Instant.now(), "web-access", "10.0.0.1", user, method, path, "",
                status, 0, ua, "raw");
    }

    @Test
    void containsIsCaseInsensitive() {
        Rule r = rule(cond("userAgent", "contains", "nikto"));
        assertTrue(matcher.matches(r, event(null, "GET", "/", 200, "Mozilla (Nikto/2.1.6)")));
    }

    @Test
    void allConditionsMustHold() {
        Rule r = rule(cond("method", "equals", "POST"), cond("statusCode", "equals", "401"));
        assertTrue(matcher.matches(r, event(null, "POST", "/login", 401, "x")));
        assertFalse(matcher.matches(r, event(null, "POST", "/login", 200, "x")));
        assertFalse(matcher.matches(r, event(null, "GET", "/login", 401, "x")));
    }

    @Test
    void anyValueMayHold() {
        Rule r = rule(cond("userAgent", "contains", "nikto", "sqlmap"));
        assertTrue(matcher.matches(r, event(null, "GET", "/", 200, "sqlmap/1.7")));
        assertFalse(matcher.matches(r, event(null, "GET", "/", 200, "Mozilla/5.0")));
    }

    @Test
    void nullFieldNeverMatches() {
        Rule r = rule(cond("username", "equals", "admin"));
        assertFalse(matcher.matches(r, event(null, "GET", "/", 200, "x")));
        assertTrue(matcher.matches(r, event("admin", "GET", "/", 200, "x")));
    }

    @Test
    void regexOperatorWorks() {
        Rule r = rule(cond("path", "regex", "^/api/Users/\\d+$"));
        assertTrue(matcher.matches(r, event(null, "GET", "/api/Users/15", 200, "x")));
        assertFalse(matcher.matches(r, event(null, "GET", "/api/Users/abc", 200, "x")));
    }
}