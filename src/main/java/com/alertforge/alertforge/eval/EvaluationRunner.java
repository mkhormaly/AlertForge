package com.alertforge.alertforge.eval;

import com.alertforge.alertforge.engine.DetectionEngine;
import com.alertforge.alertforge.engine.ThresholdTracker;
import com.alertforge.alertforge.ingest.LogReplayService;
import com.alertforge.alertforge.repository.AlertRepository;
import com.alertforge.alertforge.rules.Rule;
import com.alertforge.alertforge.rules.RuleRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * Replays the frozen dataset through the REAL detection engine, scores the alerts against the labels
 * and writes a Markdown report. Active only with the "eval" profile (property alertforge.eval.dataset).
 */
@Component
@ConditionalOnProperty(name = "alertforge.eval.dataset")
public class EvaluationRunner implements CommandLineRunner {

    private final LogReplayService replayService;
    private final DetectionEngine engine;
    private final ThresholdTracker tracker;
    private final AlertRepository alertRepository;
    private final RuleRegistry registry;
    private final String prefix;

    public EvaluationRunner(LogReplayService replayService,
                            DetectionEngine engine,
                            ThresholdTracker tracker,
                            AlertRepository alertRepository,
                            RuleRegistry registry,
                            @Value("${alertforge.eval.dataset}") String prefix) {
        this.replayService = replayService;
        this.engine = engine;
        this.tracker = tracker;
        this.alertRepository = alertRepository;
        this.registry = registry;
        this.prefix = prefix;
    }

    @Override
    public void run(String... args) throws Exception {
        Path logFile = Path.of(prefix + ".log");
        Path labelsFile = Path.of(prefix + "-labels.csv");
        Path manifestFile = Path.of(prefix + "-manifest.txt");

        DatasetIntegrity.verify(logFile, labelsFile, manifestFile);
        Map<String, Episode> episodes = LabelLoader.load(labelsFile);

        StringBuilder md = new StringBuilder();
        md.append("# AlertForge evaluation results\n\n");
        md.append("Dataset: `").append(prefix).append("` (hashes verified against the manifest)  \n");
        md.append("Run at: ").append(Instant.now()).append("\n\n");

        appendBaseline(md, runOnce(logFile, episodes));

        sweep(md, logFile, episodes, "AF-001", "count (failed logins)", new int[]{3, 4, 5, 8, 10},
                Rule.Threshold::getCount, Rule.Threshold::setCount);
        sweep(md, logFile, episodes, "AF-001", "window (seconds)", new int[]{30, 60, 120, 300},
                Rule.Threshold::getWindowSeconds, Rule.Threshold::setWindowSeconds);
        sweep(md, logFile, episodes, "AF-005", "count (ID requests)", new int[]{5, 10, 15, 20, 30},
                Rule.Threshold::getCount, Rule.Threshold::setCount);
        sweep(md, logFile, episodes, "AF-005", "window (seconds)", new int[]{15, 30, 60, 120},
                Rule.Threshold::getWindowSeconds, Rule.Threshold::setWindowSeconds);

        Path report = Path.of(prefix + "-results.md");
        Files.writeString(report, md.toString());
        System.out.println(md);
        System.out.println("Results written to " + report);
    }

    /** One complete replay with clean state; returns the scored result. */
    private EvaluationScorer.Result runOnce(Path logFile, Map<String, Episode> episodes) throws Exception {
        alertRepository.deleteAllInBatch();
        tracker.reset();
        replayService.replay(logFile, engine::process);
        List<EvaluationScorer.AlertRef> alerts = alertRepository.findAll().stream()
                .map(a -> new EvaluationScorer.AlertRef(a.getSourceIp(), a.getRuleId()))
                .toList();
        return EvaluationScorer.score(episodes.values(), alerts);
    }

    private void appendBaseline(StringBuilder md, EvaluationScorer.Result r) {
        md.append("## Baseline (rules and thresholds as shipped)\n\n");
        md.append("| Rule | Title | Attack episodes | Detected | Detection rate "
                + "| False-positive episodes | False-positive rate | Precision |\n");
        md.append("|---|---|---|---|---|---|---|---|\n");
        for (EvaluationScorer.RuleStats s : r.perRule()) {
            row(md, s.ruleId(), titleOf(s.ruleId()), s);
        }
        row(md, "ALL", "Overall", r.overall());

        md.append("\n").append(String.format(Locale.ROOT,
                "Alerts raised: %d, of which %d on normal traffic (%.2f per 1,000 normal requests); "
                        + "alerts not mapped to any episode: %d.\n\n",
                r.alerts(), r.alertsOnNormal(), r.alertsPer1000NormalRecords(), r.unmappedAlerts()));

        md.append("### Missed attack episodes (").append(r.missed().size()).append(")\n\n");
        r.missed().forEach(m -> md.append("- ").append(m).append("\n"));
        md.append("\n### False-positive episodes (").append(r.falsePositives().size()).append(")\n\n");
        r.falsePositives().forEach(f -> md.append("- ").append(f).append("\n"));
        md.append("\n");
    }

    private void row(StringBuilder md, String id, String title, EvaluationScorer.RuleStats s) {
        md.append(String.format(Locale.ROOT, "| %s | %s | %d | %d | %s | %d | %s | %s |\n",
                id, title, s.attackEpisodes(), s.detected(), pct(s.detectionRate()),
                s.falsePositiveEpisodes(), pct(s.falsePositiveRate()), pct(s.precision())));
    }

    /** Re-runs the dataset with one threshold parameter changed; always restores the original value. */
    private void sweep(StringBuilder md, Path logFile, Map<String, Episode> episodes, String ruleId,
                       String parameter, int[] values,
                       Function<Rule.Threshold, Integer> getter,
                       BiConsumer<Rule.Threshold, Integer> setter) throws Exception {
        md.append("## ").append(ruleId).append(": ").append(parameter).append("\n\n");
        Rule rule = registry.getRules().stream()
                .filter(r -> ruleId.equals(r.getId())).findFirst().orElse(null);
        if (rule == null || rule.getThreshold() == null) {
            md.append("Rule not loaded or not a threshold rule; skipped.\n\n");
            return;
        }
        Rule.Threshold threshold = rule.getThreshold();
        int original = getter.apply(threshold);

        md.append("| ").append(parameter).append(" | Detection rate | Detected "
                + "| False-positive episodes | False-positive rate | Precision |\n");
        md.append("|---|---|---|---|---|---|\n");
        try {
            for (int v : values) {
                setter.accept(threshold, v);
                EvaluationScorer.RuleStats s = runOnce(logFile, episodes).forRule(ruleId);
                if (s == null) {
                    continue;
                }
                md.append(String.format(Locale.ROOT, "| %d%s | %s | %d/%d | %d | %s | %s |\n",
                        v, v == original ? " (shipped)" : "", pct(s.detectionRate()),
                        s.detected(), s.attackEpisodes(), s.falsePositiveEpisodes(),
                        pct(s.falsePositiveRate()), pct(s.precision())));
            }
        } finally {
            setter.accept(threshold, original);
        }
        md.append("\n");
    }

    private String titleOf(String ruleId) {
        return registry.getRules().stream()
                .filter(r -> ruleId.equals(r.getId())).map(Rule::getTitle).findFirst().orElse("");
    }

    private static String pct(double value) {
        return Double.isNaN(value) ? "n/a" : String.format(Locale.ROOT, "%.1f%%", value);
    }
}
