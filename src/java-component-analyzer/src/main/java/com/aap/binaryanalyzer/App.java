package com.aap.binaryanalyzer;

import com.aap.binaryanalyzer.model.BinaryFunction;
import com.aap.binaryanalyzer.model.FeatureVector;
import com.aap.binaryanalyzer.model.SourceFile;
import com.aap.binaryanalyzer.model.SourceFunction;
import com.aap.binaryanalyzer.model.SourceProject;
import com.aap.binaryanalyzer.model.StructuredFeatures;
import com.aap.binaryanalyzer.pipeline.BinaryComponentAnalyzer;
import com.aap.binaryanalyzer.pipeline.BinaryComponentAnalyzerBuilder;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Demonstrates the binary component analyzer using mock data. In real deployments the data would
 * be gathered from Tree-sitter and Ghidra integrations.
 */
public final class App {
    public static void main(String[] args) {
        BinaryComponentAnalyzer analyzer = new BinaryComponentAnalyzerBuilder().build();

        SourceFunction sourceFunction = new SourceFunction(
                "function-1",
                "project-1",
                "compress_block",
                "void compress_block(const char*, int)",
                List.of("const char*", "int"),
                new FeatureVector(new float[]{0.3f, 0.9f, 0.1f}),
                new StructuredFeatures(Map.of("if", 2, "for", 1), Set.of("memcpy", "malloc"), Set.of("COMPRESS"))
        );
        SourceFile file = new SourceFile("src/compress.c", "hash", List.of(sourceFunction));
        SourceProject project = new SourceProject("project-1", "libcompress", "1.0.0", Instant.now(), List.of(file));
        analyzer.ingest(project);

        BinaryFunction binaryFunction = new BinaryFunction(
                "binary-1",
                "sub_401000",
                "/opt/app.bin",
                0x401000,
                new FeatureVector(new float[]{0.2f, 0.8f, 0.1f}),
                new StructuredFeatures(Map.of("if", 2), Set.of("memcpy"), Set.of("COMPRESS"))
        );

        analyzer.analyze(List.of(binaryFunction)).forEach(result -> {
            System.out.printf("Detected component %s %s with confidence %.2f and coverage %.2f%%%n",
                    result.getProjectName(), result.getVersion(), result.getConfidence(), result.getCoverage() * 100);
        });
    }
}
