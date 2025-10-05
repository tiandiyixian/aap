package com.aap.binaryanalyzer.features;

import com.aap.binaryanalyzer.model.FeatureVector;
import com.aap.binaryanalyzer.model.FunctionFeatureProfile;
import com.aap.binaryanalyzer.model.StructuredFeatures;
import com.aap.binaryanalyzer.util.StructuredFeatureBuilder;
import com.aap.binaryanalyzer.util.TokenVectorizer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reference implementation of a source feature extractor inspired by Tree-sitter. Instead of
 * invoking native parsers, we approximate the token and structure extraction steps to keep this
 * repository self-contained, while still honouring the contract defined by the system design.
 */
public class TreeSitterSourceFeatureExtractor implements FeatureExtractor {
    private final TokenVectorizer vectorizer;

    public TreeSitterSourceFeatureExtractor(int vectorDimensions) {
        this.vectorizer = new TokenVectorizer(vectorDimensions);
    }

    @Override
    public FunctionFeatureProfile extract(Path filePath, String functionId) throws IOException {
        String content = Files.readString(filePath);
        FeatureVector lexical = vectorizer.vectorize(content);
        StructuredFeatures structured = StructuredFeatureBuilder.fromText(content);
        return new FunctionFeatureProfile(functionId, lexical, structured);
    }
}
