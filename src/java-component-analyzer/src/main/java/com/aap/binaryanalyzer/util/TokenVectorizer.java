package com.aap.binaryanalyzer.util;

import com.aap.binaryanalyzer.model.FeatureVector;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * Simple hashing-based vectorizer. Each token is lowercased and hashed into a bucket,
 * enabling deterministic yet lightweight vector construction suitable for unit tests.
 */
public final class TokenVectorizer {
    private final int dimensions;

    public TokenVectorizer(int dimensions) {
        this.dimensions = dimensions;
    }

    public FeatureVector vectorize(String content) {
        Map<Integer, Integer> counts = new HashMap<>();
        StringTokenizer tokenizer = new StringTokenizer(content, "\r\n\t []{}();,.<>+-=*/!&|^%\"'`#");
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken().toLowerCase(Locale.ROOT);
            int bucket = Math.abs(Hashing.sha256(token).hashCode()) % dimensions;
            counts.merge(bucket, 1, Integer::sum);
        }
        float[] vector = new float[dimensions];
        for (Map.Entry<Integer, Integer> entry : counts.entrySet()) {
            vector[entry.getKey()] = entry.getValue();
        }
        return new FeatureVector(vector);
    }
}
