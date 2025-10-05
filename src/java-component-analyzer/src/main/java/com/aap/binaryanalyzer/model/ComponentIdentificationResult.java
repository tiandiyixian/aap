package com.aap.binaryanalyzer.model;

import java.util.Collections;
import java.util.List;

/**
 * Aggregated identification result for a single component candidate.
 */
public final class ComponentIdentificationResult {
    private final String projectId;
    private final String projectName;
    private final String version;
    private final double coverage;
    private final double averageSimilarity;
    private final double confidence;
    private final List<ComponentMatch> matches;

    public ComponentIdentificationResult(String projectId,
                                         String projectName,
                                         String version,
                                         double coverage,
                                         double averageSimilarity,
                                         double confidence,
                                         List<ComponentMatch> matches) {
        this.projectId = projectId;
        this.projectName = projectName;
        this.version = version;
        this.coverage = coverage;
        this.averageSimilarity = averageSimilarity;
        this.confidence = confidence;
        this.matches = Collections.unmodifiableList(matches);
    }

    public String getProjectId() {
        return projectId;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getVersion() {
        return version;
    }

    public double getCoverage() {
        return coverage;
    }

    public double getAverageSimilarity() {
        return averageSimilarity;
    }

    public double getConfidence() {
        return confidence;
    }

    public List<ComponentMatch> getMatches() {
        return matches;
    }
}
