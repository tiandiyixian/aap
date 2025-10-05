package com.aap.binaryanalyzer.features;

import com.aap.binaryanalyzer.model.FeatureVector;
import com.aap.binaryanalyzer.model.FunctionFeatureProfile;
import com.aap.binaryanalyzer.model.StructuredFeatures;
import com.aap.binaryanalyzer.util.StructuredFeatureBuilder;
import com.aap.binaryanalyzer.util.TokenVectorizer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Emulates the output of a Ghidra-based feature extractor by operating on textual disassembly
 * that is previously exported to disk. This allows integration tests to run quickly while the
 * production implementation can hook into the same interface to access real Ghidra features.
 */
public class GhidraBinaryFeatureExtractor implements FeatureExtractor {
    private final TokenVectorizer vectorizer;

    public GhidraBinaryFeatureExtractor(int vectorDimensions) {
        this.vectorizer = new TokenVectorizer(vectorDimensions);
    }

    @Override
    public FunctionFeatureProfile extract(Path filePath, String functionId) throws IOException {
        String disassembly = Files.readString(filePath, StandardCharsets.UTF_8);
        FeatureVector lexical = vectorizer.vectorize(disassembly);
        StructuredFeatures structured = StructuredFeatureBuilder.fromText(disassembly);
        return new FunctionFeatureProfile(functionId, lexical, structured);
    }
}
