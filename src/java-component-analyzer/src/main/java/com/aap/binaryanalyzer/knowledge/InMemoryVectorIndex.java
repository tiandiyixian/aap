package com.aap.binaryanalyzer.knowledge;

import com.aap.binaryanalyzer.model.FeatureVector;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Brute-force vector index used for unit tests. Production deployments should replace this with
 * FAISS/HNSW style ANN indices.
 */
public class InMemoryVectorIndex implements VectorIndex {
    private final Map<String, FeatureVector> vectors = new ConcurrentHashMap<>();

    @Override
    public void add(String id, FeatureVector vector) {
        vectors.put(id, vector);
    }

    @Override
    public List<String> search(FeatureVector query, int k) {
        return vectors.entrySet()
                .stream()
                .sorted(Comparator.comparingDouble((Map.Entry<String, FeatureVector> entry) ->
                        -query.cosineSimilarity(entry.getValue())))
                .limit(k)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());
    }
}
