package com.aap.binaryanalyzer.pipeline;

import com.aap.binaryanalyzer.knowledge.InMemoryKnowledgeBase;
import com.aap.binaryanalyzer.knowledge.InMemoryVectorIndex;
import com.aap.binaryanalyzer.knowledge.KnowledgeBase;
import com.aap.binaryanalyzer.knowledge.VectorIndex;
import com.aap.binaryanalyzer.matching.BinaryToSourceMatcher;
import com.aap.binaryanalyzer.matching.ComponentAggregator;

/**
 * Convenience builder creating a fully wired {@link BinaryComponentAnalyzer} using in-memory
 * components. Production deployments can construct the analyzer manually with distributed
 * implementations of the interfaces.
 */
public final class BinaryComponentAnalyzerBuilder {
    private KnowledgeBase knowledgeBase = new InMemoryKnowledgeBase();
    private VectorIndex vectorIndex = new InMemoryVectorIndex();
    private int candidateLimit = 10;
    private double coverageThreshold = 0.1;

    public BinaryComponentAnalyzerBuilder withKnowledgeBase(KnowledgeBase knowledgeBase) {
        this.knowledgeBase = knowledgeBase;
        return this;
    }

    public BinaryComponentAnalyzerBuilder withVectorIndex(VectorIndex vectorIndex) {
        this.vectorIndex = vectorIndex;
        return this;
    }

    public BinaryComponentAnalyzerBuilder withCandidateLimit(int candidateLimit) {
        this.candidateLimit = candidateLimit;
        return this;
    }

    public BinaryComponentAnalyzerBuilder withCoverageThreshold(double coverageThreshold) {
        this.coverageThreshold = coverageThreshold;
        return this;
    }

    public BinaryComponentAnalyzer build() {
        BinaryToSourceMatcher matcher = new BinaryToSourceMatcher(knowledgeBase, vectorIndex, candidateLimit);
        ComponentAggregator aggregator = new ComponentAggregator(knowledgeBase, coverageThreshold);
        return new BinaryComponentAnalyzer(knowledgeBase, vectorIndex, matcher, aggregator);
    }
}
