package com.aap.binaryanalyzer.model;

import java.util.Objects;

/**
 * Represents a function recovered from a binary.
 */
public final class BinaryFunction {
    private final String id;
    private final String name;
    private final String binaryPath;
    private final long relativeAddress;
    private final FeatureVector lexicalFeature;
    private final StructuredFeatures structuredFeatures;

    public BinaryFunction(String id,
                          String name,
                          String binaryPath,
                          long relativeAddress,
                          FeatureVector lexicalFeature,
                          StructuredFeatures structuredFeatures) {
        this.id = Objects.requireNonNull(id, "id");
        this.name = name;
        this.binaryPath = Objects.requireNonNull(binaryPath, "binaryPath");
        this.relativeAddress = relativeAddress;
        this.lexicalFeature = Objects.requireNonNull(lexicalFeature, "lexicalFeature");
        this.structuredFeatures = Objects.requireNonNull(structuredFeatures, "structuredFeatures");
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getBinaryPath() {
        return binaryPath;
    }

    public long getRelativeAddress() {
        return relativeAddress;
    }

    public FeatureVector getLexicalFeature() {
        return lexicalFeature;
    }

    public StructuredFeatures getStructuredFeatures() {
        return structuredFeatures;
    }
}
