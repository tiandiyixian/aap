package com.aap.binaryanalyzer.knowledge;

import com.aap.binaryanalyzer.model.FeatureVector;
import com.aap.binaryanalyzer.model.FunctionFeatureProfile;
import com.aap.binaryanalyzer.model.SourceFile;
import com.aap.binaryanalyzer.model.SourceFunction;
import com.aap.binaryanalyzer.model.SourceProject;
import com.aap.binaryanalyzer.model.StructuredFeatures;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;

/**
 * SQLite backed implementation of the {@link KnowledgeBase}. The database stores projects,
 * source files, function metadata, dense feature vectors and inverted indices for efficient
 * matching. Data is cached in memory for fast read paths while remaining durably persisted on
 * disk.
 */
public class SqliteKnowledgeBase implements KnowledgeBase, AutoCloseable {
    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() {
    };

    private final Connection connection;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ConcurrentMap<String, SourceProject> projectCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, SourceFunction> functionCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, FunctionFeatureProfile> profileCache = new ConcurrentHashMap<>();

    public SqliteKnowledgeBase(Path databasePath) {
        try {
            Path parent = databasePath.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Class.forName("org.sqlite.JDBC");
            this.connection = DriverManager.getConnection("jdbc:sqlite:" + databasePath.toAbsolutePath());
            try (Statement statement = connection.createStatement()) {
                statement.execute("PRAGMA journal_mode=WAL");
            }
            initialiseSchema();
        } catch (IOException | SQLException | ClassNotFoundException e) {
            throw new IllegalStateException("Failed to initialise SQLite knowledge base", e);
        }
    }

    private void initialiseSchema() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS projects (" +
                    "id TEXT PRIMARY KEY," +
                    "name TEXT NOT NULL," +
                    "version TEXT NOT NULL," +
                    "collected_at INTEGER NOT NULL)" );
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS project_files (" +
                    "project_id TEXT NOT NULL," +
                    "path TEXT NOT NULL," +
                    "content_hash TEXT NOT NULL," +
                    "PRIMARY KEY(project_id, path))");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS functions (" +
                    "id TEXT PRIMARY KEY," +
                    "project_id TEXT NOT NULL," +
                    "file_path TEXT NOT NULL," +
                    "name TEXT NOT NULL," +
                    "signature TEXT NOT NULL," +
                    "parameters_json TEXT NOT NULL)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS function_profiles (" +
                    "function_id TEXT PRIMARY KEY," +
                    "lexical BLOB NOT NULL," +
                    "structured_json TEXT NOT NULL)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS token_index (" +
                    "token TEXT NOT NULL," +
                    "function_id TEXT NOT NULL)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS string_index (" +
                    "literal TEXT NOT NULL," +
                    "function_id TEXT NOT NULL)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS token_index_token ON token_index(token)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS string_index_literal ON string_index(literal)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS function_project_idx ON functions(project_id)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS function_file_idx ON functions(project_id, file_path)");
        }
    }

    @Override
    public synchronized void addProject(SourceProject project) {
        Objects.requireNonNull(project, "project");
        try (PreparedStatement insert = connection.prepareStatement(
                "INSERT OR REPLACE INTO projects(id, name, version, collected_at) VALUES (?, ?, ?, ?)");
             PreparedStatement fileInsert = connection.prepareStatement(
                     "INSERT OR REPLACE INTO project_files(project_id, path, content_hash) VALUES (?, ?, ?)")) {
            insert.setString(1, project.getId());
            insert.setString(2, project.getName());
            insert.setString(3, project.getVersion());
            insert.setLong(4, project.getCollectedAt().getEpochSecond());
            insert.executeUpdate();

            for (SourceFile file : project.getFiles()) {
                fileInsert.setString(1, project.getId());
                fileInsert.setString(2, file.getPath());
                fileInsert.setString(3, file.getContentHash());
                fileInsert.addBatch();
            }
            fileInsert.executeBatch();
            projectCache.put(project.getId(), project);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to store project" , e);
        }
    }

    @Override
    public synchronized void addFunctionProfile(String projectId, String filePath, SourceFunction function, FunctionFeatureProfile profile) {
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(filePath, "filePath");
        Objects.requireNonNull(function, "function");
        Objects.requireNonNull(profile, "profile");
        try (PreparedStatement functionInsert = connection.prepareStatement(
                "INSERT OR REPLACE INTO functions(id, project_id, file_path, name, signature, parameters_json) VALUES (?, ?, ?, ?, ?, ?)");
             PreparedStatement profileInsert = connection.prepareStatement(
                     "INSERT OR REPLACE INTO function_profiles(function_id, lexical, structured_json) VALUES (?, ?, ?)");
             PreparedStatement tokenDelete = connection.prepareStatement("DELETE FROM token_index WHERE function_id = ?");
             PreparedStatement tokenInsert = connection.prepareStatement("INSERT INTO token_index(token, function_id) VALUES (?, ?)");
             PreparedStatement stringDelete = connection.prepareStatement("DELETE FROM string_index WHERE function_id = ?");
             PreparedStatement stringInsert = connection.prepareStatement("INSERT INTO string_index(literal, function_id) VALUES (?, ?)")
        ) {
            functionInsert.setString(1, function.getId());
            functionInsert.setString(2, projectId);
            functionInsert.setString(3, filePath);
            functionInsert.setString(4, function.getName());
            functionInsert.setString(5, function.getSignature());
            functionInsert.setString(6, mapper.writeValueAsString(function.getParameters()));
            functionInsert.executeUpdate();

            profileInsert.setString(1, profile.getFunctionId());
            profileInsert.setBytes(2, serialiseVector(profile.getLexicalVector()));
            profileInsert.setString(3, mapper.writeValueAsString(toDto(profile.getStructuredFeatures())));
            profileInsert.executeUpdate();

            tokenDelete.setString(1, function.getId());
            tokenDelete.executeUpdate();
            float[] values = profile.getLexicalVector().getValues();
            for (int i = 0; i < values.length; i++) {
                if (values[i] != 0) {
                    tokenInsert.setString(1, Integer.toString(i));
                    tokenInsert.setString(2, function.getId());
                    tokenInsert.addBatch();
                }
            }
            tokenInsert.executeBatch();

            stringDelete.setString(1, function.getId());
            stringDelete.executeUpdate();
            for (String literal : profile.getStructuredFeatures().getStringLiterals()) {
                stringInsert.setString(1, literal);
                stringInsert.setString(2, function.getId());
                stringInsert.addBatch();
            }
            stringInsert.executeBatch();

            functionCache.put(function.getId(), function);
            profileCache.put(profile.getFunctionId(), profile);
        } catch (SQLException | JsonProcessingException e) {
            throw new IllegalStateException("Failed to store function profile", e);
        }
    }

    @Override
    public Stream<SourceFunction> functionsByToken(String token) {
        List<String> functionIds = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT function_id FROM token_index WHERE token = ?")) {
            statement.setString(1, token);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    functionIds.add(resultSet.getString(1));
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to query token index", e);
        }
        return functionIds.stream().map(this::loadFunction).filter(Objects::nonNull);
    }

    @Override
    public Stream<SourceFunction> functionsByStringLiteral(String literal) {
        List<String> functionIds = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT function_id FROM string_index WHERE literal = ?")) {
            statement.setString(1, literal);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    functionIds.add(resultSet.getString(1));
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to query string index", e);
        }
        return functionIds.stream().map(this::loadFunction).filter(Objects::nonNull);
    }

    @Override
    public Stream<FunctionFeatureProfile> allProfiles() {
        List<FunctionFeatureProfile> profiles = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT function_id, lexical, structured_json FROM function_profiles");
             ResultSet resultSet = statement.executeQuery()) {
            while (resultSet.next()) {
                FunctionFeatureProfile profile = new FunctionFeatureProfile(
                        resultSet.getString(1),
                        new FeatureVector(deserialiseVector(resultSet.getBytes(2))),
                        fromDto(readStructured(resultSet.getString(3))));
                profiles.add(profile);
                profileCache.put(profile.getFunctionId(), profile);
            }
        } catch (SQLException | IOException e) {
            throw new IllegalStateException("Failed to enumerate profiles", e);
        }
        return profiles.stream();
    }

    @Override
    public Optional<SourceFunction> findFunction(String functionId) {
        return Optional.ofNullable(loadFunction(functionId));
    }

    @Override
    public Optional<FunctionFeatureProfile> findProfile(String functionId) {
        FunctionFeatureProfile profile = profileCache.get(functionId);
        if (profile != null) {
            return Optional.of(profile);
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT lexical, structured_json FROM function_profiles WHERE function_id = ?")) {
            statement.setString(1, functionId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    FunctionFeatureProfile loaded = new FunctionFeatureProfile(
                            functionId,
                            new FeatureVector(deserialiseVector(resultSet.getBytes(1))),
                            fromDto(readStructured(resultSet.getString(2))));
                    profileCache.put(functionId, loaded);
                    return Optional.of(loaded);
                }
            }
        } catch (SQLException | IOException e) {
            throw new IllegalStateException("Failed to load profile", e);
        }
        return Optional.empty();
    }

    @Override
    public Optional<String> projectIdForFunction(String functionId) {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT project_id FROM functions WHERE id = ?")) {
            statement.setString(1, functionId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return Optional.ofNullable(resultSet.getString(1));
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to lookup project id", e);
        }
        return Optional.empty();
    }

    @Override
    public Collection<SourceProject> projects() {
        ensureProjectsLoaded();
        return Collections.unmodifiableCollection(projectCache.values());
    }

    @Override
    public Optional<SourceProject> findProject(String projectId) {
        ensureProjectLoaded(projectId);
        return Optional.ofNullable(projectCache.get(projectId));
    }

    private void ensureProjectsLoaded() {
        if (!projectCache.isEmpty()) {
            return;
        }
        try (PreparedStatement statement = connection.prepareStatement("SELECT id FROM projects");
             ResultSet resultSet = statement.executeQuery()) {
            while (resultSet.next()) {
                ensureProjectLoaded(resultSet.getString(1));
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to load projects", e);
        }
    }

    private void ensureProjectLoaded(String projectId) {
        if (projectCache.containsKey(projectId)) {
            return;
        }
        try (PreparedStatement metadata = connection.prepareStatement(
                "SELECT name, version, collected_at FROM projects WHERE id = ?");
             PreparedStatement filesStmt = connection.prepareStatement(
                     "SELECT path, content_hash FROM project_files WHERE project_id = ?");
             PreparedStatement functionsStmt = connection.prepareStatement(
                     "SELECT id FROM functions WHERE project_id = ? AND file_path = ?")) {
            metadata.setString(1, projectId);
            try (ResultSet resultSet = metadata.executeQuery()) {
                if (!resultSet.next()) {
                    return;
                }
                String name = resultSet.getString(1);
                String version = resultSet.getString(2);
                Instant collectedAt = Instant.ofEpochSecond(resultSet.getLong(3));

                filesStmt.setString(1, projectId);
                try (ResultSet fileResult = filesStmt.executeQuery()) {
                    List<SourceFile> files = new ArrayList<>();
                    while (fileResult.next()) {
                        String path = fileResult.getString(1);
                        String hash = fileResult.getString(2);
                        functionsStmt.setString(1, projectId);
                        functionsStmt.setString(2, path);
                        List<SourceFunction> functions = new ArrayList<>();
                        try (ResultSet functionResult = functionsStmt.executeQuery()) {
                            while (functionResult.next()) {
                                SourceFunction function = loadFunction(functionResult.getString(1));
                                if (function != null) {
                                    functions.add(function);
                                }
                            }
                        }
                        files.add(new SourceFile(path, hash, functions));
                    }
                    SourceProject project = new SourceProject(projectId, name, version, collectedAt, files);
                    projectCache.put(projectId, project);
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to hydrate project", e);
        }
    }

    private SourceFunction loadFunction(String functionId) {
        SourceFunction cached = functionCache.get(functionId);
        if (cached != null) {
            return cached;
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT project_id, name, signature, parameters_json FROM functions WHERE id = ?")) {
            statement.setString(1, functionId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return null;
                }
                String projectId = resultSet.getString(1);
                String name = resultSet.getString(2);
                String signature = resultSet.getString(3);
                List<String> parameters = mapper.readValue(resultSet.getString(4), STRING_LIST);
                FunctionFeatureProfile profile = findProfile(functionId).orElse(null);
                StructuredFeatures structured = profile != null
                        ? profile.getStructuredFeatures()
                        : new StructuredFeatures(Map.of(), Set.of(), Set.of());
                FeatureVector lexical = profile != null
                        ? profile.getLexicalVector()
                        : new FeatureVector(new float[0]);
                SourceFunction function = new SourceFunction(functionId, projectId, name, signature, parameters, lexical, structured);
                functionCache.put(functionId, function);
                return function;
            }
        } catch (SQLException | IOException e) {
            throw new IllegalStateException("Failed to load function", e);
        }
    }

    private byte[] serialiseVector(FeatureVector vector) {
        float[] values = vector.getValues();
        ByteBuffer buffer = ByteBuffer.allocate(values.length * Float.BYTES).order(ByteOrder.LITTLE_ENDIAN);
        for (float value : values) {
            buffer.putFloat(value);
        }
        return buffer.array();
    }

    private float[] deserialiseVector(byte[] data) {
        if (data == null) {
            return new float[0];
        }
        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        float[] values = new float[data.length / Float.BYTES];
        for (int i = 0; i < values.length; i++) {
            values[i] = buffer.getFloat();
        }
        return values;
    }

    private StructuredFeaturesDto toDto(StructuredFeatures structured) {
        return new StructuredFeaturesDto(
                structured.getControlStructures(),
                structured.getApiCalls(),
                structured.getStringLiterals());
    }

    private StructuredFeaturesDto readStructured(String json) throws JsonProcessingException {
        return mapper.readValue(json, StructuredFeaturesDto.class);
    }

    private StructuredFeatures fromDto(StructuredFeaturesDto dto) {
        return new StructuredFeatures(dto.controlStructures(), dto.apiCalls(), dto.stringLiterals());
    }

    @Override
    public void close() {
        try {
            connection.close();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to close SQLite connection", e);
        }
    }

    private record StructuredFeaturesDto(Map<String, Integer> controlStructures,
                                         Set<String> apiCalls,
                                         Set<String> stringLiterals) {
    }
}
