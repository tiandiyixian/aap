package com.aap.binaryanalyzer.matching;

import com.aap.binaryanalyzer.knowledge.KnowledgeBase;
import com.aap.binaryanalyzer.model.ComponentIdentificationResult;
import com.aap.binaryanalyzer.model.ComponentMatch;
import com.aap.binaryanalyzer.model.SourceProject;

import java.util.ArrayList;
import java.util.DoubleSummaryStatistics;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Aggregates raw function matches into component level identifications using coverage and
 * similarity statistics.
 */
public class ComponentAggregator {
    private final KnowledgeBase knowledgeBase;
    private final double coverageThreshold;

    public ComponentAggregator(KnowledgeBase knowledgeBase, double coverageThreshold) {
        this.knowledgeBase = knowledgeBase;
        this.coverageThreshold = coverageThreshold;
    }

    public List<ComponentIdentificationResult> aggregate(List<ComponentMatch> matches) {
        Map<String, List<ComponentMatch>> grouped = new HashMap<>();
        for (ComponentMatch match : matches) {
            grouped.computeIfAbsent(match.getProjectId(), ignored -> new ArrayList<>()).add(match);
        }

        List<ComponentIdentificationResult> results = new ArrayList<>();
        for (Map.Entry<String, List<ComponentMatch>> entry : grouped.entrySet()) {
            Optional<SourceProject> projectOpt = knowledgeBase.findProject(entry.getKey());
            if (projectOpt.isEmpty()) {
                continue;
            }
            SourceProject project = projectOpt.get();
            double totalFunctions = project.getFiles().stream()
                    .mapToInt(file -> file.getFunctions().size())
                    .sum();
            if (totalFunctions == 0) {
                continue;
            }
            double coverage = entry.getValue().stream()
                    .map(ComponentMatch::getSourceFunctionId)
                    .distinct()
                    .count() / totalFunctions;
            if (coverage < coverageThreshold) {
                continue;
            }
            DoubleSummaryStatistics statistics = entry.getValue().stream()
                    .mapToDouble(ComponentMatch::getSimilarity)
                    .summaryStatistics();
            double confidence = statistics.getAverage() * Math.min(1.0, coverage * 2);
            results.add(new ComponentIdentificationResult(
                    project.getId(),
                    project.getName(),
                    project.getVersion(),
                    coverage,
                    statistics.getAverage(),
                    confidence,
                    entry.getValue()));
        }
        return results;
    }
}
