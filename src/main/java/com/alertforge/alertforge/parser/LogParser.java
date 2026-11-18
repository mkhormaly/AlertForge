package com.alertforge.alertforge.parser;

import java.util.Optional;

import com.alertforge.alertforge.model.Event;

public interface LogParser {
    String sourceType();
    Optional<Event> parse(String line);
}