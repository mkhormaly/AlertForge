package com.alertforge.alertforge.engine;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

/**
 * Sliding-window counter per (rule, group). Works on EVENT time (log timestamps),
 * so replaying a log gives the same result no matter how fast it is replayed.
 * Assumes events arrive in roughly chronological order.
 */
@Component
public class ThresholdTracker {

    private static final class State {
        final Deque<Instant> times = new ArrayDeque<>();
        Instant suppressedUntil;
    }

    private final Map<String, State> states = new HashMap<>();

    /**
     * Records one matching event. Returns true exactly when the threshold is reached,
     * i.e. the caller should raise an alert.
     */
    public synchronized boolean record(String ruleId, String groupKey, Instant eventTime,
                                       int count, int windowSeconds) {
        String key = ruleId + '\u0000' + groupKey;
        State state = states.computeIfAbsent(key, k -> new State());

        // Already alerted for this burst: ignore until the suppression period ends.
        if (state.suppressedUntil != null && eventTime.isBefore(state.suppressedUntil)) {
            return false;
        }

        // Drop events that have slid out of the window (boundary is inclusive).
        Instant cutoff = eventTime.minusSeconds(windowSeconds);
        while (!state.times.isEmpty() && state.times.peekFirst().isBefore(cutoff)) {
            state.times.pollFirst();
        }

        state.times.addLast(eventTime);

        if (state.times.size() >= count) {
            state.times.clear();
            state.suppressedUntil = eventTime.plusSeconds(windowSeconds);
            return true;
        }
        return false;
    }
}