package com.aap.binaryanalyzer.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * Dense vector representation used for lexical or semantic features.
 */
public final class FeatureVector {
    private final float[] values;

    public FeatureVector(float[] values) {
        this.values = Objects.requireNonNull(values, "values");
    }

    public float[] getValues() {
        return values;
    }

    public int size() {
        return values.length;
    }

    public double cosineSimilarity(FeatureVector other) {
        Objects.requireNonNull(other, "other");
        float[] otherValues = other.values;
        if (otherValues.length != values.length) {
            throw new IllegalArgumentException("Vectors must have the same dimensionality");
        }
        double dot = 0;
        double normA = 0;
        double normB = 0;
        for (int i = 0; i < values.length; i++) {
            dot += values[i] * otherValues[i];
            normA += values[i] * values[i];
            normB += otherValues[i] * otherValues[i];
        }
        if (normA == 0 || normB == 0) {
            return 0.0;
        }
        return dot / (Math.sqrt(normA) * Math.sqrt(normB));
    }

    public FeatureVector multiply(float scalar) {
        float[] scaled = Arrays.copyOf(values, values.length);
        for (int i = 0; i < scaled.length; i++) {
            scaled[i] *= scalar;
        }
        return new FeatureVector(scaled);
    }
}
