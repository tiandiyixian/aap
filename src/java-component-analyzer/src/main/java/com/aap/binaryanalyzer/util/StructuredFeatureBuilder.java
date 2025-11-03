package com.aap.binaryanalyzer.util;

import com.aap.binaryanalyzer.model.StructuredFeatures;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility to derive simple structured features from textual representations of code.
 */
public final class StructuredFeatureBuilder {
    private static final Pattern CONTROL_PATTERN = Pattern.compile("\\b(if|for|while|switch)\\b");
    private static final Pattern CALL_PATTERN = Pattern.compile("\\b([a-zA-Z_][a-zA-Z0-9_]*)\\s*\\(");
    private static final Pattern STRING_PATTERN = Pattern.compile("\"([^\"]+)\"");

    private StructuredFeatureBuilder() {
    }

    public static StructuredFeatures fromText(String text) {
        Map<String, Integer> controlCounts = new HashMap<>();
        Matcher controlMatcher = CONTROL_PATTERN.matcher(text);
        while (controlMatcher.find()) {
            String keyword = controlMatcher.group(1).toLowerCase(Locale.ROOT);
            controlCounts.merge(keyword, 1, Integer::sum);
        }

        Set<String> apiCalls = new HashSet<>();
        Matcher callMatcher = CALL_PATTERN.matcher(text);
        while (callMatcher.find()) {
            String call = callMatcher.group(1);
            if (!isControlKeyword(call)) {
                apiCalls.add(call);
            }
        }

        Set<String> strings = new HashSet<>();
        Matcher stringMatcher = STRING_PATTERN.matcher(text);
        while (stringMatcher.find()) {
            strings.add(stringMatcher.group(1));
        }

        return new StructuredFeatures(controlCounts, apiCalls, strings);
    }

    private static boolean isControlKeyword(String candidate) {
        return switch (candidate) {
            case "if", "for", "while", "switch", "return" -> true;
            default -> false;
        };
    }
}
