package com.example.IT21_FinalProject;

import jakarta.annotation.PostConstruct;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class DocumentsSigningService {

    private static final Path UPLOAD_DIR = Paths.get(System.getProperty("user.dir"), "uploads");

    private final JdbcTemplate jdbcTemplate;
    private final SigningKeyService signingKeyService;

    public DocumentsSigningService(JdbcTemplate jdbcTemplate, SigningKeyService signingKeyService) {
        this.jdbcTemplate = jdbcTemplate;
        this.signingKeyService = signingKeyService;
    }

    @PostConstruct
    public void init() {
        ensureSchemaExists();
    }

    public Map<String, Object> uploadDocument(MultipartFile file, String userId) throws Exception {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Please choose a file to upload.");
        }

        ensureSchemaExists();

        String originalName = file.getOriginalFilename();
        String safeName = originalName == null ? "document" : originalName.replaceAll("[^a-zA-Z0-9._-]", "_");
        String storedName = UUID.randomUUID().toString().substring(0, 8).toUpperCase() + "-" + safeName;
        Path targetPath = UPLOAD_DIR.resolve(storedName);

        Files.createDirectories(UPLOAD_DIR);
        Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);

        Timestamp uploadedAt = new Timestamp(System.currentTimeMillis());
        long fileSize = Files.size(targetPath);
        // Use actual DB column names: file_name, file_path, user_id, document_status, upload_date
        jdbcTemplate.update(
            "INSERT INTO document (file_name, file_path, user_id, document_status, upload_date, file_size) VALUES (?, ?, ?, 'Pending', ?, ?)",
            safeName, targetPath.toString(), userId, uploadedAt, fileSize);

        // Retrieve the DB-generated document_id
        String documentId = jdbcTemplate.queryForObject(
            "SELECT document_id FROM document WHERE file_path = ?",
            String.class, targetPath.toString());

        Map<String, Object> result = new HashMap<>();
        result.put("documentId", documentId);
        result.put("filename", safeName);
        result.put("filePath", targetPath.toString());
        result.put("status", "Pending");
        result.put("uploadedAt", uploadedAt.toString());
        return result;
    }

    public List<Map<String, Object>> getPendingDocuments(String userId) {
        try {
                    return jdbcTemplate.queryForList(
                        "SELECT document_id, file_name AS filename, upload_date AS uploaded_at FROM document " +
                        "WHERE user_id = ? AND document_status = 'Pending' ORDER BY upload_date DESC",
                        userId);
        } catch (DataAccessException ex) {
            ensureSchemaExists();
            try {
                return jdbcTemplate.queryForList(
                    "SELECT document_id, file_name AS filename, upload_date AS uploaded_at FROM document " +
                    "WHERE user_id = ? AND document_status = 'Pending' ORDER BY upload_date DESC",
                    userId);
            } catch (DataAccessException retryEx) {
                System.err.println("Failed to load pending documents: " + retryEx.getMessage());
                return java.util.Collections.emptyList();
            }
        }
    }

    /**
     * Signs a document: computes its SHA-256 hash, signs the file bytes with the
     * owner's RSA-2048 private key, stores the signature record, flips the
     * document to Signed, and writes an audit trail entry.
     */
    @Transactional
    public Map<String, Object> signDocument(String documentId, String userId) throws Exception {
        Map<String, Object> doc = jdbcTemplate.queryForMap(
            "SELECT document_id, file_name, file_path, user_id, document_status FROM document WHERE document_id = ?",
            documentId);

        if (!userId.equals(doc.get("user_id"))) {
            throw new SecurityException("You do not own this document.");
        }
        if ("Signed".equals(doc.get("document_status"))) {
            throw new IllegalStateException("This document has already been signed.");
        }

        byte[] fileBytes = Files.readAllBytes(Paths.get((String) doc.get("file_path")));

        // 1. Hash Integrity Validation input: SHA-256 of the file at signing time
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String hashHex = HexFormat.of().formatHex(digest.digest(fileBytes));

        // 2. Load (or generate, first time) this user's RSA-2048 key pair
        Map<String, Object> keyRow = signingKeyService.getOrCreateActiveKey(userId);
        String keyId = (String) keyRow.get("key_id");
        PrivateKey privateKey = loadPrivateKey((String) keyRow.get("private_key"));

        // 3. Public Key Authentication: sign the file with the private key (RSA + SHA-256)
        Signature rsaSign = Signature.getInstance("SHA256withRSA");
        rsaSign.initSign(privateKey);
        rsaSign.update(fileBytes);
        String signatureB64 = Base64.getEncoder().encodeToString(rsaSign.sign());

        // signature_id column is limited to 7 chars (e.g. 'SIG0001'), so generate a short id
        String signatureId = "SIG" + UUID.randomUUID().toString().replaceAll("[^0-9A-Za-z]", "").substring(0, 4).toUpperCase();
        Timestamp signedAt = new Timestamp(System.currentTimeMillis());

        // 4. Persist the Digital Signature Record - match actual DB columns
        String publicKeyB64 = (String) keyRow.get("public_key");
        jdbcTemplate.update(
            "INSERT INTO digital_signature " +
            "(signature_id, document_id, signer_id, signature_hash, public_key, signed_at, key_id) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            signatureId, documentId, userId, hashHex, publicKeyB64, signedAt, keyId);

        jdbcTemplate.update("UPDATE document SET document_status = 'Signed' WHERE document_id = ?", documentId);

        // 5. Audit Trail Verification: log the signing event
        jdbcTemplate.update(
                "INSERT INTO audit_trail (event_type, description, actor_id, created_at) VALUES (?, ?, ?, NOW())",
                "Document Signed",
                "Document " + documentId + " (" + doc.get("filename") + ") was signed by " + userId,
                userId);

        Map<String, Object> result = new HashMap<>();
        result.put("documentId", documentId);
        result.put("filename", doc.get("file_name"));
        result.put("signatureId", signatureId);
        result.put("algorithm", "RSA-2048 + SHA-256");
        result.put("hash", hashHex);
        result.put("signedAt", signedAt.toString());
        return result;
    }

    private void ensureSchemaExists() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS document (
                    document_id VARCHAR(64) PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    file_path TEXT NOT NULL,
                    owner_id VARCHAR(64) NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'Pending',
                    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """);
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS signing_key (
                    key_id VARCHAR(64) PRIMARY KEY,
                    user_id VARCHAR(64) NOT NULL,
                    key_type VARCHAR(32) NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'Active',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """);
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS digital_signature (
                    signature_id VARCHAR(64) PRIMARY KEY,
                    document_id VARCHAR(64) NOT NULL,
                    signer_id VARCHAR(64) NOT NULL,
                    key_id VARCHAR(64) NOT NULL,
                    algorithm VARCHAR(64) NOT NULL,
                    signature_value TEXT NOT NULL,
                    document_hash TEXT NOT NULL,
                    signed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """);
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS audit_trail (
                    audit_id BIGSERIAL PRIMARY KEY,
                    event_type VARCHAR(128) NOT NULL,
                    description TEXT NOT NULL,
                    actor_id VARCHAR(64) NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """);
    }

    private PrivateKey loadPrivateKey(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }
}