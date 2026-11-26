package com.alertforge.alertforge.eval;

/**
 * One labelled unit of the evaluation dataset: an attack, a look-alike normal case, or a background
 * user. Every episode has its own source IP, so an alert can be assigned to an episode by IP alone.
 */
public record Episode(String id, String sourceIp, String scenario, String variant,
                      boolean attack, String expectedRule, int records) {
}
