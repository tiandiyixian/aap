# Binary Component Analyzer (Java)

This module provides a reference implementation of the binary component analysis system
outlined in the design document. The code focuses on modularity and clean interfaces so that
Tree-sitter and Ghidra integrations can be plugged in later while still allowing the pipeline
to be exercised with mock data.

## Modules

* **collector** – handles acquisition of source projects and demonstrates incremental hashing.
* **features** – defines feature extractors for source and binary inputs. In this repository we
  rely on lightweight tokenisation to keep the project self-contained.
* **knowledge** – knowledge base and vector index abstractions with in-memory implementations.
* **matching** – matching engine that combines lexical vectors, structured feature overlap and
  rare feature boosts to compute similarity scores.
* **pipeline** – orchestrates project ingestion and binary analysis, exposing a simple facade and
  builder for downstream integrations.

## Building

The project uses Maven. To build the module:

```bash
mvn -f pom.xml package
```

_Note:_ The execution environment used for automated evaluation might restrict access to Maven
Central, leading to HTTP 403 errors during dependency resolution. The code itself does not rely on
external network access and can be built offline if dependencies are cached locally.

## Demonstration

Run the demo application to see end-to-end matching on synthetic data:

```bash
mvn -f pom.xml exec:java -Dexec.mainClass=com.aap.binaryanalyzer.App
```

The demo reports detected components, coverage and confidence, illustrating how the pipeline
aggregates function-level matches into component-level insights.
