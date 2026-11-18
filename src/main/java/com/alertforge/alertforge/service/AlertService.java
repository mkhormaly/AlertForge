package com.alertforge.alertforge.service;

import com.alertforge.alertforge.model.Alert;
import com.alertforge.alertforge.model.Event;
import com.alertforge.alertforge.model.Severity;
import com.alertforge.alertforge.repository.AlertRepository;
import com.alertforge.alertforge.rules.Rule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);
    private static final int MAX_EVIDENCE = 2000;

    private final AlertRepository repository;

    public AlertService(AlertRepository repository) {
        this.repository = repository;
    }

    /** Alert whose evidence is the raw log line of the triggering event. */
    public Alert raise(Rule rule, Event event) {
        return raise(rule, event, event.rawLine());
    }

    public Alert raise(Rule rule, Event event, String evidence) {
        // Severity was already validated when the rule was loaded.
        Severity severity = Severity.parse(rule.getSeverity()).orElseThrow();
        if (evidence != null && evidence.length() > MAX_EVIDENCE) {
            evidence = evidence.substring(0, MAX_EVIDENCE);
        }
        Alert alert = new Alert(rule.getId(), rule.getTitle(), severity,
                rule.getMitre().getTechnique(), rule.getMitre().getTactic(),
                event.sourceIp(), event.timestamp(), Instant.now(), evidence);
        Alert saved = repository.save(alert);
        log.info("ALERT {} [{}] {} src={} technique={}", saved.getRuleId(), severity,
                saved.getRuleTitle(), saved.getSourceIp(), saved.getMitreTechnique());
        return saved;
    }

    public long count() {
        return repository.count();
    }

    public List<Alert> findAll() {
        return repository.findAll();
    }

    /** Newest event first; severity == null means "all severities". */
    public List<Alert> find(Severity severity) {
        return severity == null
                ? repository.findAllByOrderByEventTimestampDesc()
                : repository.findBySeverityOrderByEventTimestampDesc(severity);
    }
}