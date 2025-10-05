package com.aap.binaryanalyzer.features;

import com.aap.binaryanalyzer.model.FeatureVector;
import com.aap.binaryanalyzer.model.SourceFunction;
import com.aap.binaryanalyzer.model.StructuredFeatures;
import com.aap.binaryanalyzer.util.Hashing;
import com.aap.binaryanalyzer.util.TokenVectorizer;
import io.github.treesitter.jtreesitter.Language;
import io.github.treesitter.jtreesitter.Languages;
import io.github.treesitter.jtreesitter.Node;
import io.github.treesitter.jtreesitter.Parser;
import io.github.treesitter.jtreesitter.Tree;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Tree-sitter backed feature extractor that parses C/C++ translation units and produces
 * {@link SourceFunction} objects enriched with lexical and structured characteristics.
 */
public class TreeSitterSourceFeatureExtractor {
    private static final Set<String> SUPPORTED_EXTENSIONS = Set.of(".c", ".h", ".hpp", ".cc", ".cpp", ".cxx");

    private final TokenVectorizer vectorizer;
    private final Map<SupportedLanguage, ThreadLocal<Parser>> parsers = new EnumMap<>(SupportedLanguage.class);

    public TreeSitterSourceFeatureExtractor(int vectorDimensions) {
        this.vectorizer = new TokenVectorizer(vectorDimensions);
        parsers.put(SupportedLanguage.C, ThreadLocal.withInitial(() -> configure(new Parser(), language("c"))));
        parsers.put(SupportedLanguage.CPP, ThreadLocal.withInitial(() -> configure(new Parser(), language("cpp"))));
    }

    private Parser configure(Parser parser, Language language) {
        parser.setLanguage(language);
        return parser;
    }

    private Language language(String method) {
        try {
            return (Language) Languages.class.getMethod(method).invoke(null);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Tree-sitter language not available: " + method, e);
        }
    }

    public boolean supports(Path filePath) {
        String name = filePath.getFileName().toString().toLowerCase(Locale.ROOT);
        return SUPPORTED_EXTENSIONS.stream().anyMatch(name::endsWith);
    }

    public List<SourceFunction> extract(String projectId, String relativePath, String content) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(relativePath, "relativePath");
        Objects.requireNonNull(content, "content");

        SupportedLanguage language = SupportedLanguage.fromPath(relativePath);
        if (language == SupportedLanguage.UNKNOWN) {
            return List.of();
        }
        Parser parser = parsers.get(language).get();
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        Tree tree = parse(parser, bytes, content);
        Node root = tree.getRootNode();
        List<SourceFunction> functions = new ArrayList<>();
        collectFunctions(projectId, relativePath, bytes, root, functions);
        return functions;
    }

    private Tree parse(Parser parser, byte[] bytes, String content) {
        try {
            return (Tree) Parser.class.getMethod("parseString", String.class).invoke(parser, content);
        } catch (ReflectiveOperationException ignored) {
            try {
                return (Tree) Parser.class.getMethod("parse", byte[].class).invoke(parser, (Object) bytes);
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("Tree-sitter parser API not supported", e);
            }
        }
    }

    private void collectFunctions(String projectId,
                                  String relativePath,
                                  byte[] bytes,
                                  Node node,
                                  List<SourceFunction> sink) {
        if ("function_definition".equals(node.getType())) {
            sink.add(buildFunction(projectId, relativePath, bytes, node));
        }
        int childCount = node.getChildCount();
        for (int i = 0; i < childCount; i++) {
            collectFunctions(projectId, relativePath, bytes, node.getChild(i), sink);
        }
    }

    private SourceFunction buildFunction(String projectId,
                                         String relativePath,
                                         byte[] bytes,
                                         Node node) {
        Node body = node.getChildByFieldName("body");
        String functionText = slice(bytes, node);
        String bodyText = body == null ? functionText : slice(bytes, body);

        String name = extractFunctionName(node, bytes);
        List<String> parameters = extractParameters(node, bytes);
        String returnType = extractReturnType(node, bytes);
        String signature = (returnType == null || returnType.isBlank() ? "" : returnType + " ") +
                name + "(" + String.join(", ", parameters) + ")";

        FeatureVector lexical = vectorizer.vectorize(bodyText);
        StructuredFeatures structured = extractStructuredFeatures(node, bytes);
        String identifierSeed = projectId + ':' + relativePath + ':' + name + ':' + node.getStartByte();
        String functionId = Hashing.sha256(identifierSeed);

        return new SourceFunction(functionId,
                projectId,
                name,
                signature,
                parameters,
                lexical,
                structured);
    }

    private String extractFunctionName(Node node, byte[] bytes) {
        Node declarator = node.getChildByFieldName("declarator");
        Node identifier = findFirst(declarator, "identifier");
        return identifier == null ? "anonymous" : slice(bytes, identifier);
    }

    private List<String> extractParameters(Node node, byte[] bytes) {
        Node declarator = node.getChildByFieldName("declarator");
        Node parameterList = findFirst(declarator, "parameter_list");
        if (parameterList == null) {
            return List.of();
        }
        List<String> parameters = new ArrayList<>();
        int namedChildren = parameterList.getNamedChildCount();
        for (int i = 0; i < namedChildren; i++) {
            Node child = parameterList.getNamedChild(i);
            if ("parameter_declaration".equals(child.getType())) {
                parameters.add(normaliseWhitespace(slice(bytes, child)));
            }
        }
        return parameters;
    }

    private String extractReturnType(Node node, byte[] bytes) {
        Node specifiers = node.getChildByFieldName("declaration_specifiers");
        if (specifiers == null) {
            return "";
        }
        return normaliseWhitespace(slice(bytes, specifiers));
    }

    private StructuredFeatures extractStructuredFeatures(Node node, byte[] bytes) {
        Map<String, Integer> control = new HashMap<>();
        Set<String> calls = new HashSet<>();
        Set<String> strings = new HashSet<>();
        collectStructured(node, bytes, control, calls, strings);
        return new StructuredFeatures(control, calls, strings);
    }

    private void collectStructured(Node node,
                                   byte[] bytes,
                                   Map<String, Integer> control,
                                   Set<String> calls,
                                   Set<String> strings) {
        switch (node.getType()) {
            case "if_statement" -> control.merge("if", 1, Integer::sum);
            case "while_statement", "do_statement" -> control.merge("while", 1, Integer::sum);
            case "for_statement" -> control.merge("for", 1, Integer::sum);
            case "switch_statement" -> control.merge("switch", 1, Integer::sum);
            case "call_expression" -> {
                Node identifier = findFirst(node, "identifier");
                if (identifier != null) {
                    calls.add(slice(bytes, identifier));
                }
            }
            case "string_literal" -> strings.add(trimQuotes(slice(bytes, node)));
            default -> {
            }
        }
        int childCount = node.getChildCount();
        for (int i = 0; i < childCount; i++) {
            collectStructured(node.getChild(i), bytes, control, calls, strings);
        }
    }

    private Node findFirst(Node node, String type) {
        if (node == null) {
            return null;
        }
        if (type.equals(node.getType())) {
            return node;
        }
        int childCount = node.getChildCount();
        for (int i = 0; i < childCount; i++) {
            Node result = findFirst(node.getChild(i), type);
            if (result != null) {
                return result;
            }
        }
        return null;
    }

    private String slice(byte[] bytes, Node node) {
        int start = node.getStartByte();
        int end = node.getEndByte();
        return new String(bytes, start, end - start, StandardCharsets.UTF_8);
    }

    private String normaliseWhitespace(String value) {
        return value.replaceAll("\\s+", " ").trim();
    }

    private String trimQuotes(String literal) {
        String trimmed = literal.trim();
        if (trimmed.length() >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
            return trimmed.substring(1, trimmed.length() - 1);
        }
        return trimmed;
    }

    private enum SupportedLanguage {
        C,
        CPP,
        UNKNOWN;

        static SupportedLanguage fromPath(String path) {
            String lower = path.toLowerCase(Locale.ROOT);
            if (lower.endsWith(".c") || lower.endsWith(".h")) {
                return C;
            }
            if (lower.endsWith(".cc") || lower.endsWith(".cpp") || lower.endsWith(".hpp") || lower.endsWith(".cxx")) {
                return CPP;
            }
            return UNKNOWN;
        }
    }
}
