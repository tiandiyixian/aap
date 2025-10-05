package com.aap.binaryanalyzer.knowledge;

import com.aap.binaryanalyzer.model.FeatureVector;

import java.util.List;

/**
 * Approximate nearest neighbour index abstraction.
 */
public interface VectorIndex {

    void add(String id, FeatureVector vector);

    List<String> search(FeatureVector query, int k);
}
