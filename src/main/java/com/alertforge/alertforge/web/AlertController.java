package com.alertforge.alertforge.web;

import com.alertforge.alertforge.model.Severity;
import com.alertforge.alertforge.service.AlertService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService service;

    public AlertController(AlertService service) {
        this.service = service;
    }

    @GetMapping
    public List<AlertResponse> list(
            @RequestParam(name = "severity", required = false) String severity) {
        Severity filter = null;
        if (severity != null && !severity.isBlank()) {
            filter = Severity.parse(severity).orElseThrow(() -> new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "severity must be one of LOW, MEDIUM, HIGH, CRITICAL"));
        }
        return service.find(filter).stream().map(AlertResponse::from).toList();
    }
}