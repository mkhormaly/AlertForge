package com.alertforge.alertforge.engine;

import com.alertforge.alertforge.model.Alert;
import com.alertforge.alertforge.model.Event;
import com.alertforge.alertforge.rules.EventFields;
import com.alertforge.alertforge.rules.Rule;
import com.alertforge.alertforge.rules.RuleRegistry;
import com.alertforge.alertforge.service.AlertService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class DetectionEngine {

    private final RuleRegistry registry;
    private final EventMatcher matcher;
    private final ThresholdTracker tracker;
    private final AlertService alertService;

    public DetectionEngine(RuleRegistry registry, EventMatcher matcher,
                           ThresholdTracker tracker, AlertService alertService) {
        this.registry = registry;
        this.matcher = matcher;
        this.tracker = tracker;
        this.alertService = alertService;
    }

    /** Runs one event through every rule; returns the alerts it caused. */
    public List<Alert> process(Event event) {
        List<Alert> raised = new ArrayList<>();
        for (Rule rule : registry.getRules()) {
            if (!matcher.matches(rule, event)) {
                continue;
            }
            if ("match".equals(rule.getType())) {
                raised.add(alertService.raise(rule, event));
            } else if ("threshold".equals(rule.getType())) {
                Rule.Threshold t = rule.getThreshold();
                String groupKey = EventFields.valueOf(event, t.getGroupBy());
                if (groupKey == null) {
                    continue; // cannot group an event that lacks the field
                }
                if (tracker.record(rule.getId(), groupKey, event.timestamp(),
                        t.getCount(), t.getWindowSeconds())) {
                    String evidence = "Threshold reached: " + t.getCount()
                            + " matching events within " + t.getWindowSeconds()
                            + "s for " + t.getGroupBy() + "=" + groupKey
                            + "\nLast event: " + event.rawLine();
                    raised.add(alertService.raise(rule, event, evidence));
                }
            }
        }
        return raised;
    }
}