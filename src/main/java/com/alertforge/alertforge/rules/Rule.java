package com.alertforge.alertforge.rules;

import java.util.ArrayList;
import java.util.List;

/** Mutable on purpose: SnakeYAML fills it through setters. */
public class Rule {
    private String id;
    private String title;
    private String description;
    private String severity;
    private String type;                 // "match" or "threshold"
    private Mitre mitre;
    private List<Condition> conditions = new ArrayList<>();
    private Threshold threshold;         // only for type: threshold

    public static class Mitre {
        private String tactic;
        private String technique;
        private String name;
        public String getTactic() { return tactic; }
        public void setTactic(String tactic) { this.tactic = tactic; }
        public String getTechnique() { return technique; }
        public void setTechnique(String technique) { this.technique = technique; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }

    public static class Condition {
        private String field;
        private String operator;         // equals | contains | startsWith | regex
        private List<String> values = new ArrayList<>();
        public String getField() { return field; }
        public void setField(String field) { this.field = field; }
        public String getOperator() { return operator; }
        public void setOperator(String operator) { this.operator = operator; }
        public List<String> getValues() { return values; }
        public void setValues(List<String> values) { this.values = values; }
    }

    public static class Threshold {
        private int count;
        private int windowSeconds;
        private String groupBy;
        public int getCount() { return count; }
        public void setCount(int count) { this.count = count; }
        public int getWindowSeconds() { return windowSeconds; }
        public void setWindowSeconds(int windowSeconds) { this.windowSeconds = windowSeconds; }
        public String getGroupBy() { return groupBy; }
        public void setGroupBy(String groupBy) { this.groupBy = groupBy; }
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public Mitre getMitre() { return mitre; }
    public void setMitre(Mitre mitre) { this.mitre = mitre; }
    public List<Condition> getConditions() { return conditions; }
    public void setConditions(List<Condition> conditions) { this.conditions = conditions; }
    public Threshold getThreshold() { return threshold; }
    public void setThreshold(Threshold threshold) { this.threshold = threshold; }
}