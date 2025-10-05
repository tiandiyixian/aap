package com.aap.binaryanalyzer.pipeline;

import com.aap.binaryanalyzer.knowledge.KnowledgeBase;
import com.aap.binaryanalyzer.knowledge.VectorIndex;
import com.aap.binaryanalyzer.matching.BinaryToSourceMatcher;
import com.aap.binaryanalyzer.matching.ComponentAggregator;
import com.aap.binaryanalyzer.model.BinaryFunction;
import com.aap.binaryanalyzer.model.ComponentIdentificationResult;
import com.aap.binaryanalyzer.model.ComponentMatch;
import com.aap.binaryanalyzer.model.FunctionFeatureProfile;
import com.aap.binaryanalyzer.model.SourceFile;
import com.aap.binaryanalyzer.model.SourceFunction;
import com.aap.binaryanalyzer.model.SourceProject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * High-level facade orchestrating ingestion and matching workflow.
 */
public class BinaryComponentAnalyzer {
    private final KnowledgeBase knowledgeBase;
    private final VectorIndex vectorIndex;
    private final BinaryToSourceMatcher matcher;
    private final ComponentAggregator aggregator;
    private final Collection<SourceProject> ingestedProjects = new CopyOnWriteArrayList<>();

    public BinaryComponentAnalyzer(KnowledgeBase knowledgeBase,
                                   VectorIndex vectorIndex,
                                   BinaryToSourceMatcher matcher,
                                   ComponentAggregator aggregator) {
        this.knowledgeBase = knowledgeBase;
        this.vectorIndex = vectorIndex;
        this.matcher = matcher;
        this.aggregator = aggregator;
    }

    public void ingest(SourceProject project) {
        knowledgeBase.addProject(project);
        for (SourceFile file : project.getFiles()) {
            for (SourceFunction function : file.getFunctions()) {
                FunctionFeatureProfile profile = new FunctionFeatureProfile(
                        function.getId(),
                        function.getLexicalFeature(),
                        function.getStructuredFeatures());
                knowledgeBase.addFunctionProfile(project.getId(), function, profile);
                vectorIndex.add(function.getId(), function.getLexicalFeature());
            }
        }
        ingestedProjects.add(project);
    }

    public List<ComponentIdentificationResult> analyze(List<BinaryFunction> functions) {
        List<ComponentMatch> matches = new ArrayList<>();
        for (BinaryFunction function : functions) {
            matches.addAll(matcher.match(function));
        }
        return aggregator.aggregate(matches);
    }

    public Collection<SourceProject> getIngestedProjects() {
        return ingestedProjects;
    }
}
