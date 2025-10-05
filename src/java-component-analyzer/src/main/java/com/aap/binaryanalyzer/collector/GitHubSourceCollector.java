package com.aap.binaryanalyzer.collector;

import com.aap.binaryanalyzer.features.TreeSitterSourceFeatureExtractor;
import com.aap.binaryanalyzer.model.SourceFile;
import com.aap.binaryanalyzer.model.SourceFunction;
import com.aap.binaryanalyzer.model.SourceProject;
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
    private final TreeSitterSourceFeatureExtractor extractor;

    public GitHubSourceCollector(Path rootDirectory,
                                 Predicate<Path> fileFilter,
                                 TreeSitterSourceFeatureExtractor extractor,
                                 int workers) {
        this.rootDirectory = rootDirectory;
        this.fileFilter = fileFilter;
        this.executorService = Executors.newFixedThreadPool(workers);
        this.extractor = extractor;
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
                    .filter(extractor::supports)
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
            String relativePath = projectPath.relativize(filePath).toString();
            String content = Files.readString(filePath);
            String hash = Hashing.sha256(content);
            List<SourceFunction> functions = extractor.extract(projectId, relativePath, content);
            return new SourceFile(relativePath, hash, functions);
        } catch (IOException e) {
            LOGGER.warn("Failed to read file {}", filePath, e);
            return new SourceFile(projectPath.relativize(filePath).toString(), "", Collections.emptyList());
        } catch (RuntimeException e) {
            LOGGER.warn("Tree-sitter failed to parse {}", filePath, e);
            return new SourceFile(projectPath.relativize(filePath).toString(), "", Collections.emptyList());
        }
    }
}
