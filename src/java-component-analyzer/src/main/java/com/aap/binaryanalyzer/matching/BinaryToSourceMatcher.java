package com.aap.binaryanalyzer.matching;

import com.aap.binaryanalyzer.knowledge.KnowledgeBase;
import com.aap.binaryanalyzer.knowledge.VectorIndex;
import com.aap.binaryanalyzer.model.BinaryFunction;
import com.aap.binaryanalyzer.model.ComponentMatch;
import com.aap.binaryanalyzer.model.FeatureVector;
import com.aap.binaryanalyzer.model.FunctionFeatureProfile;
import com.aap.binaryanalyzer.model.SourceFunction;
import com.aap.binaryanalyzer.model.StructuredFeatures;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Performs feature based matching between binary and source functions. It combines vector
 * similarity, structured feature overlap and rare feature weighting.
 */
public class BinaryToSourceMatcher {
    private final KnowledgeBase knowledgeBase;
    private final VectorIndex vectorIndex;
    private final int candidateLimit;

    public BinaryToSourceMatcher(KnowledgeBase knowledgeBase, VectorIndex vectorIndex, int candidateLimit) {
        this.knowledgeBase = knowledgeBase;
        this.vectorIndex = vectorIndex;
        this.candidateLimit = candidateLimit;
    }

    public List<ComponentMatch> match(BinaryFunction binaryFunction) {
        FeatureVector queryVector = binaryFunction.getLexicalFeature();
        List<String> vectorCandidates = vectorIndex.search(queryVector, candidateLimit);
        Set<String> candidateIds = new HashSet<>(vectorCandidates);

        StructuredFeatures structured = binaryFunction.getStructuredFeatures();
        structured.getStringLiterals().forEach(literal ->
                knowledgeBase.functionsByStringLiteral(literal).forEach(function -> candidateIds.add(function.getId())));

        List<ComponentMatch> matches = new ArrayList<>();
        for (String candidateId : candidateIds) {
            Optional<SourceFunction> candidateOpt = knowledgeBase.findFunction(candidateId);
            if (candidateOpt.isEmpty()) {
                continue;
            }
            SourceFunction candidate = candidateOpt.get();
            Optional<String> projectId = knowledgeBase.projectIdForFunction(candidateId);
            if (projectId.isEmpty()) {
                continue;
            }
            FunctionFeatureProfile profile = knowledgeBase.findProfile(candidateId)
                    .orElseGet(() -> new FunctionFeatureProfile(candidate.getId(),
                            candidate.getLexicalFeature(),
                            candidate.getStructuredFeatures()));
            double cosine = queryVector.cosineSimilarity(profile.getLexicalVector());
            double structureScore = structured.jaccardSimilarity(profile.getStructuredFeatures());
            double rareBonus = rareFeatureBoost(structured, profile.getStructuredFeatures());
            double similarity = 0.7 * cosine + 0.3 * structureScore + rareBonus;
            double confidence = similarity / (1 + Math.log1p(structured.rareFeatureScore()));
            matches.add(new ComponentMatch(projectId.get(),
                    binaryFunction.getId(),
                    candidate.getId(),
                    similarity,
                    confidence));
        }

        return matches.stream()
                .sorted((a, b) -> Double.compare(b.getSimilarity(), a.getSimilarity()))
                .limit(candidateLimit)
                .collect(Collectors.toList());
    }

    private double rareFeatureBoost(StructuredFeatures binaryFeatures, StructuredFeatures sourceFeatures) {
        Set<String> intersection = new HashSet<>(binaryFeatures.getStringLiterals());
        intersection.retainAll(sourceFeatures.getStringLiterals());
        return intersection.size() * 0.05;
    }
}
