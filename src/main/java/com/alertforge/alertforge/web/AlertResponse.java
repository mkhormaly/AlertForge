package com.alertforge.alertforge.web;

import com.alertforge.alertforge.model.Alert;

public record AlertResponse(
        Long id,
        String ruleId,
        String ruleTitle,
        String severity,
        String mitreTechnique,
        String mitreTactic,
        String sourceIp,
        String eventTimestamp,   // ISO-8601, e.g. 2026-11-16T07:17:10Z
        String createdAt,
        String evidence) {

    public static AlertResponse from(Alert a) {
        return new AlertResponse(
                a.getId(),
                a.getRuleId(),
                a.getRuleTitle(),
                a.getSeverity().name(),
                a.getMitreTechnique(),
                a.getMitreTactic(),
                a.getSourceIp(),
                a.getEventTimestamp().toString(),
                a.getCreatedAt().toString(),
                a.getEvidence());
    }
}