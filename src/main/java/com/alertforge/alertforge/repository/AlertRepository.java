package com.alertforge.alertforge.repository;

import com.alertforge.alertforge.model.Alert;
import com.alertforge.alertforge.model.Severity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {

    List<Alert> findAllByOrderByEventTimestampDesc();

    List<Alert> findBySeverityOrderByEventTimestampDesc(Severity severity);
}