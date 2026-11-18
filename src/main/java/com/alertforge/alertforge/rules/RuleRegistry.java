package com.alertforge.alertforge.rules;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

@Component
public class RuleRegistry {

    private static final Logger log = LoggerFactory.getLogger(RuleRegistry.class);

    private final List<Rule> rules;

    public RuleRegistry(RuleLoader loader,
                        @Value("${alertforge.rules.dir:rules}") String dir) throws IOException {
        this.rules = List.copyOf(loader.loadAll(Path.of(dir)));
        rules.forEach(r -> log.info("Loaded rule {} [{}] {} ({})",
                r.getId(), r.getType(), r.getTitle(), r.getSeverity()));
    }

    public List<Rule> getRules() {
        return rules;
    }
}