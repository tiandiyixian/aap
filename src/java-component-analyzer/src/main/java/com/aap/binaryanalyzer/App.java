package com.aap.binaryanalyzer;

import com.aap.binaryanalyzer.features.GhidraBinaryFeatureExtractor;
import com.aap.binaryanalyzer.features.TreeSitterSourceFeatureExtractor;
import com.aap.binaryanalyzer.model.BinaryFunction;
import com.aap.binaryanalyzer.model.FunctionFeatureProfile;
import com.aap.binaryanalyzer.model.SourceFile;
import com.aap.binaryanalyzer.model.SourceFunction;
import com.aap.binaryanalyzer.model.SourceProject;
import com.aap.binaryanalyzer.pipeline.BinaryComponentAnalyzer;
import com.aap.binaryanalyzer.pipeline.BinaryComponentAnalyzerBuilder;
import com.aap.binaryanalyzer.util.Hashing;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * Demonstrates the binary component analyzer by ingesting Tree-sitter derived source functions
 * and matching them against a Ghidra feature export represented as JSON.
 */
public final class App {
    public static void main(String[] args) throws Exception {
        TreeSitterSourceFeatureExtractor sourceExtractor = new TreeSitterSourceFeatureExtractor(512);
        GhidraBinaryFeatureExtractor ghidraExtractor = new GhidraBinaryFeatureExtractor(512);

        String projectId = Hashing.sha256("libcompress");
        String sourceCode = """
                #include <string.h>\n\n"
                + "static char buffer[1024];\n\n"
                + "void compress_block(const char* input, int length) {\n"
                + "    if (length <= 0) {\n"
                + "        return;\n"
                + "    }\n"
                + "    memcpy(buffer, input, length);\n"
                + "}\n";
        List<SourceFunction> functions = sourceExtractor.extract(projectId, "compress.c", sourceCode);
        if (functions.isEmpty()) {
            System.err.println("Tree-sitter did not yield any functions for the demo project.");
            return;
        }
        SourceFile file = new SourceFile("compress.c", Hashing.sha256(sourceCode), functions);
        SourceProject project = new SourceProject(projectId, "libcompress", "1.0.0", Instant.now(), List.of(file));

        try (BinaryComponentAnalyzer analyzer = new BinaryComponentAnalyzerBuilder().build()) {
            analyzer.ingest(project);

            Path tempJson = Files.createTempFile("binary-function", ".json");
            try {
                String ghidraDocument = """
                        {
                          "id": "binary-1",
                          "disassembly": "push rbp; if (length <= 0) goto LAB_401020; memcpy(buffer,input,length);",
                          "pcode": "...",
                          "strings": ["buffer"],
                          "calls": ["memcpy"],
                          "controlFlow": {"if": 1}
                        }
                        """;
                Files.writeString(tempJson, ghidraDocument);
                FunctionFeatureProfile binaryProfile = ghidraExtractor.extract(tempJson, "binary-1");
                BinaryFunction binaryFunction = new BinaryFunction(
                        "binary-1",
                        "FUN_401000",
                        "demo.bin",
                        0x401000L,
                        binaryProfile.getLexicalVector(),
                        binaryProfile.getStructuredFeatures());

                analyzer.analyze(List.of(binaryFunction)).forEach(result ->
                        System.out.printf("Detected component %s %s with confidence %.2f and coverage %.2f%%%n",
                                result.getProjectName(), result.getVersion(), result.getConfidence(), result.getCoverage() * 100));
            } finally {
                Files.deleteIfExists(tempJson);
            }
        }
    }
}
