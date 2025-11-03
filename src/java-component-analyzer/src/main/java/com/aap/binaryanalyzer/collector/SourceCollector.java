package com.aap.binaryanalyzer.collector;

import com.aap.binaryanalyzer.model.SourceProject;

import java.io.IOException;
import java.util.stream.Stream;

/**
 * Collects source projects from external providers such as GitHub.
 */
public interface SourceCollector {

    /**
     * Initiates collection and returns a stream of source projects.
     *
     * @throws IOException when remote communication fails.
     */
    Stream<SourceProject> collect() throws IOException;
}
