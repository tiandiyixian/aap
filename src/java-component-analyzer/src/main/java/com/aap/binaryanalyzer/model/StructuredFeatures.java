package com.aap.binaryanalyzer.model;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Structured features extracted from source or binary code such as control-flow statistics
 * and API invocations.
 */
public final class StructuredFeatures {
    private final Map<String, Integer> controlStructures;
    private final Set<String> apiCalls;
    private final Set<String> stringLiterals;

    public StructuredFeatures(Map<String, Integer> controlStructures,
                              Set<String> apiCalls,
                              Set<String> stringLiterals) {
        this.controlStructures = Collections.unmodifiableMap(controlStructures);
        this.apiCalls = Collections.unmodifiableSet(apiCalls);
        this.stringLiterals = Collections.unmodifiableSet(stringLiterals);
    }

    public Map<String, Integer> getControlStructures() {
        return controlStructures;
    }

    public Set<String> getApiCalls() {
        return apiCalls;
    }

    public Set<String> getStringLiterals() {
        return stringLiterals;
    }

    public int rareFeatureScore() {
        return stringLiterals.size() * 3 + apiCalls.size() * 2;
    }

    public double jaccardSimilarity(StructuredFeatures other) {
        Objects.requireNonNull(other, "other");
        int intersection = 0;
        for (String call : apiCalls) {
            if (other.apiCalls.contains(call)) {
                intersection++;
            }
        }
        int union = apiCalls.size() + other.apiCalls.size() - intersection;
        double callScore = union == 0 ? 1.0 : (double) intersection / union;

        int stringIntersection = 0;
        for (String literal : stringLiterals) {
            if (other.stringLiterals.contains(literal)) {
                stringIntersection++;
            }
        }
        int stringUnion = stringLiterals.size() + other.stringLiterals.size() - stringIntersection;
        double literalScore = stringUnion == 0 ? 1.0 : (double) stringIntersection / stringUnion;

        return 0.6 * callScore + 0.4 * literalScore;
    }
}
