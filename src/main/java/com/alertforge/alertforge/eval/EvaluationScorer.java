package com.alertforge.alertforge.eval;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Scores alerts against the labelled episodes. Unit of evaluation = the episode.
 * <ul>
 *   <li>Attack episode DETECTED: at least one alert from its expected rule came from its IP.</li>
 *   <li>Normal episode FALSE POSITIVE: at least one alert (of the rule in question, or of any rule
 *       for the overall row) came from its IP.</li>
 *   <li>Detection rate = detected / attack episodes; false-positive rate = false-positive episodes
 *       / normal episodes; precision = detected / (detected + false-positive episodes).</li>
 * </ul>
 * Plain Java on purpose: no Spring, no database, easy to unit test.
 */
public final class EvaluationScorer {

    private EvaluationScorer() {
    }

    public record AlertRef(String sourceIp, String ruleId) {
    }

    public record RuleStats(String ruleId, int attackEpisodes, int detected,
                            int normalEpisodes, int falsePositiveEpisodes) {

        /** Percent; NaN when there are no attack episodes for this rule. */
        public double detectionRate() {
            return attackEpisodes == 0 ? Double.NaN : 100.0 * detected / attackEpisodes;
        }

        public double falsePositiveRate() {
            return normalEpisodes == 0 ? Double.NaN : 100.0 * falsePositiveEpisodes / normalEpisodes;
        }

        /** Percent; NaN when the rule raised no alert at all. */
        public double precision() {
            int raised = detected + falsePositiveEpisodes;
            return raised == 0 ? Double.NaN : 100.0 * detected / raised;
        }
    }

    public record Result(List<RuleStats> perRule, RuleStats overall, int alerts, int alertsOnNormal,
                         int unmappedAlerts, long normalRecords,
                         List<String> missed, List<String> falsePositives) {

        public double alertsPer1000NormalRecords() {
            return normalRecords == 0 ? Double.NaN : 1000.0 * alertsOnNormal / normalRecords;
        }

        public RuleStats forRule(String ruleId) {
            return perRule.stream().filter(s -> s.ruleId().equals(ruleId)).findFirst().orElse(null);
        }
    }

    public static Result score(Collection<Episode> episodes, List<AlertRef> alerts) {
        Map<String, Episode> byIp = new HashMap<>();
        for (Episode e : episodes) {
            byIp.put(e.sourceIp(), e);
        }

        Map<String, Set<String>> rulesByIp = new HashMap<>();
        int unmapped = 0;
        int onNormal = 0;
        for (AlertRef a : alerts) {
            Episode e = byIp.get(a.sourceIp());
            if (e == null) {
                unmapped++;
                continue;
            }
            if (!e.attack()) {
                onNormal++;
            }
            rulesByIp.computeIfAbsent(a.sourceIp(), k -> new TreeSet<>()).add(a.ruleId());
        }

        int normalEpisodes = 0;
        long normalRecords = 0;
        Set<String> ruleIds = new TreeSet<>();
        for (Episode e : episodes) {
            if (e.attack()) {
                ruleIds.add(e.expectedRule());
            } else {
                normalEpisodes++;
                normalRecords += e.records();
            }
        }
        for (AlertRef a : alerts) {
            ruleIds.add(a.ruleId());
        }

        List<RuleStats> perRule = new ArrayList<>();
        for (String rule : ruleIds) {
            int attack = 0;
            int detected = 0;
            int falsePositive = 0;
            for (Episode e : episodes) {
                Set<String> fired = rulesByIp.getOrDefault(e.sourceIp(), Set.of());
                if (e.attack()) {
                    if (rule.equals(e.expectedRule())) {
                        attack++;
                        if (fired.contains(rule)) {
                            detected++;
                        }
                    }
                } else if (fired.contains(rule)) {
                    falsePositive++;
                }
            }
            perRule.add(new RuleStats(rule, attack, detected, normalEpisodes, falsePositive));
        }

        int attackTotal = 0;
        int detectedTotal = 0;
        int falsePositiveTotal = 0;
        List<String> missed = new ArrayList<>();
        List<String> falsePositives = new ArrayList<>();
        for (Episode e : episodes) {
            Set<String> fired = rulesByIp.getOrDefault(e.sourceIp(), Set.of());
            if (e.attack()) {
                attackTotal++;
                if (fired.contains(e.expectedRule())) {
                    detectedTotal++;
                } else {
                    missed.add(e.id() + " [" + e.scenario() + "/" + e.variant() + "] expected "
                            + e.expectedRule() + ", rules that fired: "
                            + (fired.isEmpty() ? "none" : String.join(", ", fired)));
                }
            } else if (!fired.isEmpty()) {
                falsePositiveTotal++;
                falsePositives.add(e.id() + " [" + e.scenario() + "/" + e.variant()
                        + "] alerts from: " + String.join(", ", fired));
            }
        }
        RuleStats overall = new RuleStats("ALL", attackTotal, detectedTotal,
                normalEpisodes, falsePositiveTotal);

        return new Result(perRule, overall, alerts.size(), onNormal, unmapped, normalRecords,
                missed, falsePositives);
    }
}
