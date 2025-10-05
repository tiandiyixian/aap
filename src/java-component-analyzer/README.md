# Binary Component Analyzer (Java)

This module provides a reference implementation of the binary component analysis system
outlined in the design document. The implementation integrates [tree-sitter](https://tree-sitter.github.io)
for C/C++ feature extraction, persists the source knowledge base in SQLite, and consumes
JSON exports produced by Ghidra headless scripts to build binary function profiles.

## Modules

* **collector** – handles acquisition of source projects from on-disk Git mirrors, invokes the
  Tree-sitter extractor, and derives stable identifiers and file-level hashes.
* **features** – includes the Tree-sitter backed source extractor and a Ghidra JSON reader that
  converts exported disassembly/p-code into lexical and structured features.
* **knowledge** – provides a SQLite-backed knowledge base that stores projects, functions,
  inverted indices, and serialised dense vectors.
* **matching** – matching engine that combines lexical vectors, structured feature overlap and
  rare feature boosts to compute similarity scores.
* **pipeline** – orchestrates project ingestion and binary analysis, exposing a simple facade and
  builder for downstream integrations.

## Building

The project uses Maven. To build the module:

```bash
mvn -f pom.xml package
```

> **Note**: The execution environment used for automated evaluation might restrict access to Maven
> Central, leading to HTTP 403 errors during dependency resolution. The project only depends on the
> declared Maven artefacts (tree-sitter, SQLite, SLF4J, Jackson). If the dependencies are cached
> locally the build can run entirely offline.

## Demonstration

Run the demo application to see end-to-end matching on synthetic data:

```bash
mvn -f pom.xml exec:java -Dexec.mainClass=com.aap.binaryanalyzer.App
```

The demo parses a C snippet with Tree-sitter, stores the function in the SQLite knowledge base,
reads a JSON feature document that mirrors the output of a Ghidra headless export, and reports
the detected component alongside coverage and confidence metrics.

The default builder persists data under `data/knowledge-base.db`; the path can be overridden
via `BinaryComponentAnalyzerBuilder#withSqliteKnowledgeBase(Path)` when embedding the library
into other tooling.
