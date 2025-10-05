package com.aap.binaryanalyzer.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Metadata describing a source project retrieved from GitHub or other sources.
 */
public final class SourceProject {
    private final String id;
    private final String name;
    private final String version;
    private final Instant collectedAt;
    private final List<SourceFile> files;

    public SourceProject(String id, String name, String version, Instant collectedAt, List<SourceFile> files) {
        this.id = Objects.requireNonNull(id, "id");
        this.name = Objects.requireNonNull(name, "name");
        this.version = Objects.requireNonNull(version, "version");
        this.collectedAt = Objects.requireNonNull(collectedAt, "collectedAt");
        this.files = List.copyOf(files);
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public Instant getCollectedAt() {
        return collectedAt;
    }

    public List<SourceFile> getFiles() {
        return files;
    }
}
