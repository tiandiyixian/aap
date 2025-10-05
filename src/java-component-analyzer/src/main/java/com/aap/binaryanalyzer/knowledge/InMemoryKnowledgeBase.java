package com.aap.binaryanalyzer.knowledge;

import com.aap.binaryanalyzer.model.FunctionFeatureProfile;
import com.aap.binaryanalyzer.model.SourceFunction;
import com.aap.binaryanalyzer.model.SourceProject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;

/**
 * Lightweight in-memory knowledge base suitable for prototyping and tests. The real system
 * would replace this with persistent storage and distributed indices.
 */
public class InMemoryKnowledgeBase implements KnowledgeBase {
    private final ConcurrentMap<String, SourceProject> projects = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, SourceFunction> functions = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, FunctionFeatureProfile> profiles = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> functionToProject = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> functionToFile = new ConcurrentHashMap<>();
    private final Map<String, List<String>> tokenIndex = new HashMap<>();
    private final Map<String, List<String>> stringIndex = new HashMap<>();

    @Override
    public void addProject(SourceProject project) {
        projects.put(project.getId(), project);
    }

    @Override
    public synchronized void addFunctionProfile(String projectId, String filePath, SourceFunction function, FunctionFeatureProfile profile) {
        functions.put(function.getId(), function);
        functionToProject.put(function.getId(), projectId);
        functionToFile.put(function.getId(), filePath);
        profiles.put(function.getId(), profile);
        indexTokens(profile, function.getId());
        indexStrings(function, function.getId());
    }

    private void indexTokens(FunctionFeatureProfile profile, String functionId) {
        float[] values = profile.getLexicalVector().getValues();
        for (int i = 0; i < values.length; i++) {
            if (values[i] > 0) {
                tokenIndex.computeIfAbsent(Integer.toString(i), ignored -> new ArrayList<>()).add(functionId);
            }
        }
    }

    private void indexStrings(SourceFunction function, String functionId) {
        function.getStructuredFeatures().getStringLiterals()
                .forEach(literal -> stringIndex.computeIfAbsent(literal, ignored -> new ArrayList<>()).add(functionId));
    }

    @Override
    public Stream<SourceFunction> functionsByToken(String token) {
        return tokenIndex.getOrDefault(token, List.of()).stream().map(functions::get);
    }

    @Override
    public Stream<SourceFunction> functionsByStringLiteral(String literal) {
        return stringIndex.getOrDefault(literal, List.of()).stream().map(functions::get);
    }

    @Override
    public Stream<FunctionFeatureProfile> allProfiles() {
        return profiles.values().stream();
    }

    @Override
    public Optional<SourceFunction> findFunction(String functionId) {
        return Optional.ofNullable(functions.get(functionId));
    }

    @Override
    public Optional<FunctionFeatureProfile> findProfile(String functionId) {
        return Optional.ofNullable(profiles.get(functionId));
    }

    @Override
    public Collection<SourceProject> projects() {
        return Collections.unmodifiableCollection(projects.values());
    }

    @Override
    public Optional<String> projectIdForFunction(String functionId) {
        return Optional.ofNullable(functionToProject.get(functionId));
    }

    @Override
    public Optional<SourceProject> findProject(String projectId) {
        return Optional.ofNullable(projects.get(projectId));
    }
}
