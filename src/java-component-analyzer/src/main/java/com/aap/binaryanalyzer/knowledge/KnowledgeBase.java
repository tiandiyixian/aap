package com.aap.binaryanalyzer.knowledge;

import com.aap.binaryanalyzer.model.FunctionFeatureProfile;
import com.aap.binaryanalyzer.model.SourceFunction;
import com.aap.binaryanalyzer.model.SourceProject;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Abstraction that stores feature profiles and metadata about source functions.
 */
public interface KnowledgeBase extends AutoCloseable {

    void addProject(SourceProject project);

    void addFunctionProfile(String projectId, String filePath, SourceFunction function, FunctionFeatureProfile profile);

    Stream<SourceFunction> functionsByToken(String token);

    Stream<SourceFunction> functionsByStringLiteral(String literal);

    Stream<FunctionFeatureProfile> allProfiles();

    Optional<SourceFunction> findFunction(String functionId);

    Optional<FunctionFeatureProfile> findProfile(String functionId);

    Optional<String> projectIdForFunction(String functionId);

    Collection<SourceProject> projects();

    Optional<SourceProject> findProject(String projectId);

    @Override
    default void close() throws Exception {
    }
}
