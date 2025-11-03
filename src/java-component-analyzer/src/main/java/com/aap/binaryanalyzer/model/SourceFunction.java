package com.aap.binaryanalyzer.model;

import java.util.List;
import java.util.Objects;

/**
 * Representation of a function parsed from source code.
 */
public final class SourceFunction {
    private final String id;
    private final String projectId;
    private final String name;
    private final String signature;
    private final List<String> parameters;
    private final FeatureVector lexicalFeature;
    private final StructuredFeatures structuredFeatures;

    public SourceFunction(String id,
                          String projectId,
                          String name,
                          String signature,
                          List<String> parameters,
                          FeatureVector lexicalFeature,
                          StructuredFeatures structuredFeatures) {
        this.id = Objects.requireNonNull(id, "id");
        this.projectId = Objects.requireNonNull(projectId, "projectId");
        this.name = Objects.requireNonNull(name, "name");
        this.signature = Objects.requireNonNull(signature, "signature");
        this.parameters = List.copyOf(parameters);
        this.lexicalFeature = Objects.requireNonNull(lexicalFeature, "lexicalFeature");
        this.structuredFeatures = Objects.requireNonNull(structuredFeatures, "structuredFeatures");
    }

    public String getId() {
        return id;
    }

    public String getProjectId() {
        return projectId;
    }

    public String getName() {
        return name;
    }

    public String getSignature() {
        return signature;
    }

    public List<String> getParameters() {
        return parameters;
    }

    public FeatureVector getLexicalFeature() {
        return lexicalFeature;
    }

    public StructuredFeatures getStructuredFeatures() {
        return structuredFeatures;
    }
}
