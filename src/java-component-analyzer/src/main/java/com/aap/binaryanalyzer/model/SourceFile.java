package com.aap.binaryanalyzer.model;

import java.util.List;
import java.util.Objects;

/**
 * Representation of a source file and the functions parsed from it.
 */
public final class SourceFile {
    private final String path;
    private final String contentHash;
    private final List<SourceFunction> functions;

    public SourceFile(String path, String contentHash, List<SourceFunction> functions) {
        this.path = Objects.requireNonNull(path, "path");
        this.contentHash = Objects.requireNonNull(contentHash, "contentHash");
        this.functions = List.copyOf(functions);
    }

    public String getPath() {
        return path;
    }

    public String getContentHash() {
        return contentHash;
    }

    public List<SourceFunction> getFunctions() {
        return functions;
    }
}
