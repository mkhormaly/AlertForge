package com.alertforge.alertforge.ingest;

import com.alertforge.alertforge.engine.DetectionEngine;
import com.alertforge.alertforge.service.AlertService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;

@Component
@ConditionalOnProperty(name = "alertforge.replay.file")
public class StartupReplayRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(StartupReplayRunner.class);

    private final LogReplayService replayService;
    private final DetectionEngine engine;
    private final AlertService alertService;
    private final String file;

    public StartupReplayRunner(LogReplayService replayService,
                               DetectionEngine engine,
                               AlertService alertService,
                               @Value("${alertforge.replay.file}") String file) {
        this.replayService = replayService;
        this.engine = engine;
        this.alertService = alertService;
        this.file = file;
    }

    @Override
    public void run(String... args) {
        try {
            var result = replayService.replay(Path.of(file), e -> {
                log.info("EVENT {} {} {} {} -> {}",
                        e.timestamp(), e.sourceIp(), e.method(), e.path(), e.statusCode());
                engine.process(e);
            });
            log.info("Replay finished: total={} parsed={} skipped={} alerts={}",
                    result.totalLines(), result.parsed(), result.skipped(), alertService.count());
        } catch (IOException ex) {
            log.error("Could not replay {}: {}", file, ex.getMessage());
        }
    }
}