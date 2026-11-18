package com.alertforge.alertforge.engine;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThresholdTrackerTest {

    private static final Instant BASE = Instant.parse("2026-11-16T07:00:00Z");
    private static final int COUNT = 5;
    private static final int WINDOW = 60;

    private final ThresholdTracker tracker = new ThresholdTracker();

    private static Instant t(int seconds) {
        return BASE.plusSeconds(seconds);
    }

    private boolean rec(String rule, String group, int seconds) {
        return tracker.record(rule, group, t(seconds), COUNT, WINDOW);
    }

    @Test
    void firesOnFifthEventWithinWindow() {
        assertFalse(rec("R1", "A", 0));
        assertFalse(rec("R1", "A", 1));
        assertFalse(rec("R1", "A", 2));
        assertFalse(rec("R1", "A", 3));
        assertTrue(rec("R1", "A", 4));
    }

    @Test
    void doesNotFireWhenEventsAreTooSpreadOut() {
        // one event every 20 s: never more than 4 inside any 60 s window
        for (int s = 0; s <= 100; s += 20) {
            assertFalse(rec("R1", "A", s), "second " + s);
        }
    }

    @Test
    void windowBoundaryIsInclusive() {
        // 5 events spanning exactly 60 s -> fires
        rec("R1", "EXACT", 0);
        rec("R1", "EXACT", 15);
        rec("R1", "EXACT", 30);
        rec("R1", "EXACT", 45);
        assertTrue(rec("R1", "EXACT", 60));

        // 5 events spanning 61 s -> the first one has slid out, no alert
        rec("R1", "LATE", 0);
        rec("R1", "LATE", 15);
        rec("R1", "LATE", 30);
        rec("R1", "LATE", 45);
        assertFalse(rec("R1", "LATE", 61));
    }

    @Test
    void groupsAreIndependent() {
        for (int s = 0; s < 4; s++) {
            assertFalse(rec("R1", "A", s));
            assertFalse(rec("R1", "B", s));
        }
        assertTrue(rec("R1", "A", 4));   // A reaches 5 on its own
        assertTrue(rec("R1", "B", 4));   // B reaches 5 on its own
    }

    @Test
    void rulesAreIndependent() {
        for (int s = 0; s < 4; s++) {
            rec("R1", "A", s);
        }
        assertFalse(rec("R2", "A", 4));  // same group, different rule: its own counter
        assertTrue(rec("R1", "A", 4));
    }

    @Test
    void suppressesDuplicatesThenReArms() {
        for (int s = 0; s < 4; s++) {
            rec("R1", "A", s);
        }
        assertTrue(rec("R1", "A", 4));          // alert, suppressed until second 64

        for (int s = 5; s <= 63; s += 6) {      // sustained attack during suppression
            assertFalse(rec("R1", "A", s), "second " + s);
        }

        // after suppression a fresh burst is needed
        assertFalse(rec("R1", "A", 64));
        assertFalse(rec("R1", "A", 65));
        assertFalse(rec("R1", "A", 66));
        assertFalse(rec("R1", "A", 67));
        assertTrue(rec("R1", "A", 68));
    }
}