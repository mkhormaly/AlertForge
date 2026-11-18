package com.alertforge.alertforge.rules;

import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.error.YAMLException;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

@Component
public class RuleLoader {

    private final RuleValidator validator;

    public RuleLoader(RuleValidator validator) {
        this.validator = validator;
    }

    public List<Rule> loadAll(Path dir) throws IOException {
        if (!Files.isDirectory(dir)) {
            throw new RuleLoadException("Rules directory not found: " + dir.toAbsolutePath());
        }
        List<Path> files;
        try (Stream<Path> listing = Files.list(dir)) {
            files = listing
                    .filter(p -> p.toString().endsWith(".yml") || p.toString().endsWith(".yaml"))
                    .sorted()
                    .toList();
        }
        List<Rule> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (Path file : files) {
            Rule rule = loadFile(file);
            if (!ids.add(rule.getId())) {
                throw new RuleLoadException(file.getFileName() + ": duplicate rule id " + rule.getId());
            }
            rules.add(rule);
        }
        return rules;
    }

    public Rule loadFile(Path file) throws IOException {
        Rule rule;
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            // A new Yaml per file: the class is not thread-safe.
            Yaml yaml = new Yaml(new Constructor(Rule.class, new LoaderOptions()));
            rule = yaml.load(reader);
        } catch (YAMLException e) {
            throw new RuleLoadException(file.getFileName() + ": invalid YAML: " + e.getMessage(), e);
        }
        if (rule == null) {
            throw new RuleLoadException(file.getFileName() + ": file is empty");
        }
        List<String> errors = validator.validate(rule);
        if (!errors.isEmpty()) {
            throw new RuleLoadException(file.getFileName() + ": " + String.join("; ", errors));
        }
        return rule;
    }
}