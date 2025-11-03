package com.aap.binaryanalyzer.model;

import java.util.Objects;

/**
 * Bundles lexical and structured features for use by the matching engine.
 */
public final class FunctionFeatureProfile {
    private final String functionId;
    private final FeatureVector lexicalVector;
    private final StructuredFeatures structuredFeatures;

    public FunctionFeatureProfile(String functionId,
                                  FeatureVector lexicalVector,
                                  StructuredFeatures structuredFeatures) {
        this.functionId = Objects.requireNonNull(functionId, "functionId");
        this.lexicalVector = Objects.requireNonNull(lexicalVector, "lexicalVector");
        this.structuredFeatures = Objects.requireNonNull(structuredFeatures, "structuredFeatures");
    }

    public String getFunctionId() {
        return functionId;
    }

    public FeatureVector getLexicalVector() {
        return lexicalVector;
    }

    public StructuredFeatures getStructuredFeatures() {
        return structuredFeatures;
    }
}
