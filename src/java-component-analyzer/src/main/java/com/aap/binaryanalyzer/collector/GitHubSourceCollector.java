package com.aap.binaryanalyzer.collector;

import com.aap.binaryanalyzer.model.FeatureVector;
import com.aap.binaryanalyzer.model.SourceFile;
import com.aap.binaryanalyzer.model.SourceFunction;
import com.aap.binaryanalyzer.model.SourceProject;
import com.aap.binaryanalyzer.model.StructuredFeatures;
import com.aap.binaryanalyzer.util.Hashing;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Simplified GitHub collector that reads local mirrors of repositories. In a production
 * system this component would communicate with the GitHub API and git clients, but here we
 * keep the logic focused on filtering, hashing and versioning so the overall architecture
 * can be exercised in tests.
 */
public class GitHubSourceCollector implements SourceCollector {
    private static final Logger LOGGER = LoggerFactory.getLogger(GitHubSourceCollector.class);

    private final Path rootDirectory;
    private final Predicate<Path> fileFilter;
    private final ExecutorService executorService;

    public GitHubSourceCollector(Path rootDirectory, Predicate<Path> fileFilter, int workers) {
        this.rootDirectory = rootDirectory;
        this.fileFilter = fileFilter;
        this.executorService = Executors.newFixedThreadPool(workers);
    }

    @Override
    public Stream<SourceProject> collect() throws IOException {
        if (!Files.exists(rootDirectory)) {
            return Stream.empty();
        }

        List<Path> projects = Files.list(rootDirectory)
                .filter(Files::isDirectory)
                .collect(Collectors.toList());

        List<Future<SourceProject>> tasks = new ArrayList<>();
        for (Path projectPath : projects) {
            tasks.add(executorService.submit(() -> parseProject(projectPath)));
        }

        return tasks.stream().flatMap(future -> {
            try {
                SourceProject project = future.get();
                return project == null ? Stream.empty() : Stream.of(project);
            } catch (Exception e) {
                LOGGER.warn("Failed to parse project", e);
                return Stream.empty();
            }
        });
    }

    private SourceProject parseProject(Path projectPath) {
        try {
            String projectId = Hashing.sha256(projectPath.toString());
            List<SourceFile> files = Files.walk(projectPath)
                    .filter(Files::isRegularFile)
                    .filter(fileFilter)
                    .map(path -> parseFile(projectId, projectPath, path))
                    .filter(f -> !f.getFunctions().isEmpty())
                    .collect(Collectors.toList());

            if (files.isEmpty()) {
                return null;
            }

            String version = "local";
            return new SourceProject(projectId,
                    projectPath.getFileName().toString(),
                    version,
                    Instant.now(),
                    files);
        } catch (IOException e) {
            LOGGER.warn("Failed to walk project {}", projectPath, e);
            return null;
        }
    }

    private SourceFile parseFile(String projectId, Path projectPath, Path filePath) {
        try {
            String content = Files.readString(filePath);
            String hash = Hashing.sha256(content);
            // In this reference implementation we do not parse real functions. We place holders so that
            // the knowledge base can be populated during tests.
            SourceFunction placeholderFunction = new SourceFunction(
                    Hashing.sha256(projectPath.relativize(filePath).toString()),
                    projectId,
                    filePath.getFileName().toString(),
                    "void placeholder()",
                    Collections.emptyList(),
                    new SourceFunctionPlaceholderVector(),
                    SourceFunctionPlaceholderVector.STRUCTURED
            );
            return new SourceFile(projectPath.relativize(filePath).toString(), hash, List.of(placeholderFunction));
        } catch (IOException e) {
            LOGGER.warn("Failed to read file {}", filePath, e);
            return new SourceFile(projectPath.relativize(filePath).toString(), "", Collections.emptyList());
        }
    }

    /**
     * Simple placeholder vector to make the module self-contained without real Tree-sitter
     * integration. In production, this would be replaced by the feature extractor output.
     */
    private static class SourceFunctionPlaceholderVector extends FeatureVector {
        private static final StructuredFeatures STRUCTURED = new StructuredFeatures(Collections.emptyMap(), Collections.emptySet(), Collections.emptySet());

        SourceFunctionPlaceholderVector() {
            super(new float[]{1, 0, 0});
        }
    }
}
