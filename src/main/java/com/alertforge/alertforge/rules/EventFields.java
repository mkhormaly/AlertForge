package com.alertforge.alertforge.rules;

import com.alertforge.alertforge.model.Event;

import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/** The only Event fields a rule may reference, with a way to read each as text. */
public final class EventFields {

    private static final Map<String, Function<Event, String>> ACCESSORS = Map.of(
            "sourceIp", Event::sourceIp,
            "username", Event::username,
            "method", Event::method,
            "path", Event::path,
                        "query", Event::query,
            // whole request target: path plus "?" plus query (both already decoded)
            "target", e -> e.query() == null || e.query().isEmpty()
                    ? e.path() : e.path() + "?" + e.query(),
            "statusCode", e -> String.valueOf(e.statusCode()),
            "userAgent", Event::userAgent);

    private EventFields() {}

    public static boolean isKnown(String field) {
        return field != null && ACCESSORS.containsKey(field);
    }

    public static Set<String> names() {
        return ACCESSORS.keySet();
    }

    public static String valueOf(Event event, String field) {
        Function<Event, String> accessor = ACCESSORS.get(field);
        return accessor == null ? null : accessor.apply(event);
    }
}