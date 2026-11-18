package com.alertforge.alertforge.engine;

import com.alertforge.alertforge.model.Event;
import com.alertforge.alertforge.rules.EventFields;
import com.alertforge.alertforge.rules.Rule;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Decides whether ONE event satisfies ONE rule's conditions.
 * All conditions must hold (AND); within a condition any value may hold (OR).
 * Comparison is case-insensitive. A null field (e.g. no username) never matches.
 */
@Component
public class EventMatcher {

    private final Map<String, Pattern> regexCache = new ConcurrentHashMap<>();

    public boolean matches(Rule rule, Event event) {
        for (Rule.Condition condition : rule.getConditions()) {
            if (!conditionHolds(condition, event)) {
                return false;
            }
        }
        return true;
    }

    private boolean conditionHolds(Rule.Condition c, Event event) {
        String actual = EventFields.valueOf(event, c.getField());
        if (actual == null) {
            return false;
        }
        String actualLower = actual.toLowerCase(Locale.ROOT);
        for (String expected : c.getValues()) {
            if (valueMatches(c.getOperator(), actual, actualLower, expected)) {
                return true;
            }
        }
        return false;
    }

    private boolean valueMatches(String operator, String actual, String actualLower, String expected) {
        String expectedLower = expected.toLowerCase(Locale.ROOT);
        return switch (operator) {
            case "equals" -> actualLower.equals(expectedLower);
            case "contains" -> actualLower.contains(expectedLower);
            case "startsWith" -> actualLower.startsWith(expectedLower);
            case "regex" -> regex(expected).matcher(actual).find();
            default -> false;
        };
    }

    private Pattern regex(String pattern) {
        return regexCache.computeIfAbsent(pattern,
                p -> Pattern.compile(p, Pattern.CASE_INSENSITIVE));
    }
}