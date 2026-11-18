package com.alertforge.alertforge.rules;

import com.alertforge.alertforge.model.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@Component
public class RuleValidator {

    private static final Set<String> OPERATORS = Set.of("equals", "contains", "startsWith", "regex");
    private static final Set<String> TYPES = Set.of("match", "threshold");
    private static final Pattern TECHNIQUE = Pattern.compile("^T\\d{4}(\\.\\d{3})?$");

    public List<String> validate(Rule r) {
        List<String> errors = new ArrayList<>();

        if (blank(r.getId())) errors.add("id is required");
        if (blank(r.getTitle())) errors.add("title is required");
        if (Severity.parse(r.getSeverity()).isEmpty()) {
            errors.add("severity must be one of low, medium, high, critical (was: " + r.getSeverity() + ")");
        }
        if (r.getType() == null || !TYPES.contains(r.getType())) {
            errors.add("type must be 'match' or 'threshold' (was: " + r.getType() + ")");
        }

        if (r.getMitre() == null || blank(r.getMitre().getTechnique())
                || !TECHNIQUE.matcher(r.getMitre().getTechnique()).matches()) {
            errors.add("mitre.technique is required and must look like T1110 or T1110.001");
        }

        if (r.getConditions() == null || r.getConditions().isEmpty()) {
            errors.add("at least one condition is required");
        } else {
            int i = 1;
            for (Rule.Condition c : r.getConditions()) {
                String where = "condition #" + i++;
                if (!EventFields.isKnown(c.getField())) {
                    errors.add(where + ": unknown field '" + c.getField()
                            + "' (allowed: " + EventFields.names() + ")");
                }
                if (c.getOperator() == null || !OPERATORS.contains(c.getOperator())) {
                    errors.add(where + ": operator must be one of " + OPERATORS);
                }
                if (c.getValues() == null || c.getValues().isEmpty()) {
                    errors.add(where + ": values must not be empty");
                } else if ("regex".equals(c.getOperator())) {
                    for (String v : c.getValues()) {
                        try {
                            Pattern.compile(v);
                        } catch (PatternSyntaxException e) {
                            errors.add(where + ": invalid regex '" + v + "'");
                        }
                    }
                }
            }
        }

        if ("threshold".equals(r.getType())) {
            Rule.Threshold t = r.getThreshold();
            if (t == null) {
                errors.add("type 'threshold' requires a threshold block");
            } else {
                if (t.getCount() < 1) errors.add("threshold.count must be at least 1");
                if (t.getWindowSeconds() < 1) errors.add("threshold.windowSeconds must be at least 1");
                if (!EventFields.isKnown(t.getGroupBy())) {
                    errors.add("threshold.groupBy must be a known field (allowed: " + EventFields.names() + ")");
                }
            }
        } else if ("match".equals(r.getType()) && r.getThreshold() != null) {
            errors.add("type 'match' must not have a threshold block");
        }
        return errors;
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }
}