package com.alertforge.alertforge.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "alerts")
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String ruleId;

    private String ruleTitle;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    private String mitreTechnique;
    private String mitreTactic;
    private String sourceIp;

    @Column(nullable = false)
    private Instant eventTimestamp;   // when the suspicious event happened (from the log)

    @Column(nullable = false)
    private Instant createdAt;        // when AlertForge raised the alert

    @Column(length = 2000)
    private String evidence;          // raw log line(s) that triggered it

    protected Alert() {
        // required by JPA
    }

    public Alert(String ruleId, String ruleTitle, Severity severity, String mitreTechnique,
                 String mitreTactic, String sourceIp, Instant eventTimestamp,
                 Instant createdAt, String evidence) {
        this.ruleId = ruleId;
        this.ruleTitle = ruleTitle;
        this.severity = severity;
        this.mitreTechnique = mitreTechnique;
        this.mitreTactic = mitreTactic;
        this.sourceIp = sourceIp;
        this.eventTimestamp = eventTimestamp;
        this.createdAt = createdAt;
        this.evidence = evidence;
    }

    public Long getId() { return id; }
    public String getRuleId() { return ruleId; }
    public String getRuleTitle() { return ruleTitle; }
    public Severity getSeverity() { return severity; }
    public String getMitreTechnique() { return mitreTechnique; }
    public String getMitreTactic() { return mitreTactic; }
    public String getSourceIp() { return sourceIp; }
    public Instant getEventTimestamp() { return eventTimestamp; }
    public Instant getCreatedAt() { return createdAt; }
    public String getEvidence() { return evidence; }
}