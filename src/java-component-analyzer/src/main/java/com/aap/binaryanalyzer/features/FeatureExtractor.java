package com.aap.binaryanalyzer.features;

import com.aap.binaryanalyzer.model.FunctionFeatureProfile;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Common contract for feature extractors.
 */
public interface FeatureExtractor {

    FunctionFeatureProfile extract(Path filePath, String functionId) throws IOException;
}
