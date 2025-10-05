package com.aap.binaryanalyzer.model;

import java.util.Objects;

/**
 * Represents the match between a binary and source function.
 */
public final class ComponentMatch {
    private final String projectId;
    private final String binaryFunctionId;
    private final String sourceFunctionId;
    private final double similarity;
    private final double confidence;

    public ComponentMatch(String projectId,
                          String binaryFunctionId,
                          String sourceFunctionId,
                          double similarity,
                          double confidence) {
        this.projectId = Objects.requireNonNull(projectId, "projectId");
        this.binaryFunctionId = Objects.requireNonNull(binaryFunctionId, "binaryFunctionId");
        this.sourceFunctionId = Objects.requireNonNull(sourceFunctionId, "sourceFunctionId");
        this.similarity = similarity;
        this.confidence = confidence;
    }

    public String getProjectId() {
        return projectId;
    }

    public String getBinaryFunctionId() {
        return binaryFunctionId;
    }

    public String getSourceFunctionId() {
        return sourceFunctionId;
    }

    public double getSimilarity() {
        return similarity;
    }

    public double getConfidence() {
        return confidence;
    }
}
