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
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
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

    @Transactional
    public Map<String, Object> uploadDocument(MultipartFile file, String userId) throws Exception {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Please choose a file to upload.");
        }

        ensureSchemaExists();
        String documentId = generateDocumentId();
        String tempUuid = UUID.randomUUID().toString();
        String originalName = file.getOriginalFilename();
        String safeName = originalName == null ? "document" : originalName.replaceAll("[^a-zA-Z0-9._-]", "_");
        String storedName = tempUuid.substring(0, 8).toUpperCase() + "-" + safeName;
        Path targetPath = UPLOAD_DIR.resolve(storedName);

        Files.createDirectories(UPLOAD_DIR);
        Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);

        byte[] fileBytes = Files.readAllBytes(targetPath);
        String fileHash = computeSha256Hex(fileBytes);
        Timestamp uploadedAt = new Timestamp(System.currentTimeMillis());
        long fileSize = Files.size(targetPath);

        jdbcTemplate.update(
            "INSERT INTO document (document_id, file_name, file_path, user_id, document_status, upload_date, file_size, file_hash_original) VALUES (?, ?, ?, ?, 'PENDING', ?, ?, ?)",
            documentId, safeName, targetPath.toString(), userId, uploadedAt, fileSize, fileHash);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("documentId", documentId);
        result.put("filename", safeName);
        result.put("filePath", targetPath.toString());
        result.put("status", "PENDING");
        result.put("hash", fileHash);
        result.put("uploadedAt", uploadedAt.toString());
        return result;
    }

    private String generateDocumentId() {
        Integer nextNumber = jdbcTemplate.queryForObject(
                "SELECT COALESCE(MAX(CAST(SUBSTRING(document_id, 4) AS INTEGER)), 0) + 1 FROM document WHERE document_id LIKE 'DOC%';",
                Integer.class);
        return String.format("DOC%04d", nextNumber);
    }

    public List<Map<String, Object>> getPendingDocuments(String userId) {
        try {
            return jdbcTemplate.queryForList(
                "SELECT document_id, file_name AS filename, upload_date AS uploaded_at FROM document " +
                "WHERE user_id = ? AND document_status = 'PENDING' ORDER BY upload_date DESC",
                userId);
        } catch (DataAccessException ex) {
            ensureSchemaExists();
            try {
                return jdbcTemplate.queryForList(
                    "SELECT document_id, file_name AS filename, upload_date AS uploaded_at FROM document " +
                    "WHERE user_id = ? AND document_status = 'PENDING' ORDER BY upload_date DESC",
                    userId);
            } catch (DataAccessException retryEx) {
                System.err.println("Failed to load pending documents: " + retryEx.getMessage());
                return java.util.Collections.emptyList();
            }
        }
    }

    @Transactional
    public Map<String, Object> signDocument(String documentId, String userId) throws Exception {
        Map<String, Object> doc = jdbcTemplate.queryForMap(
            "SELECT document_id, file_name, file_path, user_id, document_status FROM document WHERE document_id = ?",
            documentId);

        if (!userId.equals(doc.get("user_id"))) {
            throw new SecurityException("You do not own this document.");
        }
        if ("SIGNED".equalsIgnoreCase(String.valueOf(doc.get("document_status")))) {
            throw new IllegalStateException("This document has already been signed.");
        }

        byte[] fileBytes = Files.readAllBytes(Paths.get((String) doc.get("file_path")));
        String hashHex = computeSha256Hex(fileBytes);

        Map<String, Object> keyRow = signingKeyService.getOrCreateActiveKey(userId);
        String keyId = (String) keyRow.get("key_id");
        PrivateKey privateKey = loadPrivateKey((String) keyRow.get("private_key"));

        Signature rsaSign = Signature.getInstance("SHA256withRSA");
        rsaSign.initSign(privateKey);
        rsaSign.update(fileBytes);
        String signatureB64 = Base64.getEncoder().encodeToString(rsaSign.sign());

        String signatureId = "SIG" + UUID.randomUUID().toString().replaceAll("[^0-9A-Za-z]", "").substring(0, 4).toUpperCase();
        Timestamp signedAt = new Timestamp(System.currentTimeMillis());
        String publicKeyB64 = (String) keyRow.get("public_key");

        jdbcTemplate.update(
            "INSERT INTO digital_signature (signature_id, document_id, signer_id, signature_hash, public_key, signature_value, signed_at, key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            signatureId, documentId, userId, hashHex, publicKeyB64, signatureB64, signedAt, keyId);

        jdbcTemplate.update("UPDATE document SET document_status = 'SIGNED', file_hash_original = ? WHERE document_id = ?", hashHex, documentId);
        logAudit("Document Signed", "Document " + documentId + " (" + doc.get("file_name") + ") was signed by " + userId, userId);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("documentId", documentId);
        result.put("filename", doc.get("file_name"));
        result.put("signatureId", signatureId);
        result.put("algorithm", "RSA-2048 + SHA-256");
        result.put("hash", hashHex);
        result.put("signedAt", signedAt.toString());
        return result;
    }

    @Transactional
    public Map<String, Object> verifyDocument(String documentId, String verifierId) throws Exception {
        Map<String, Object> doc = jdbcTemplate.queryForMap(
            "SELECT document_id, file_name, file_path, file_hash_original FROM document WHERE document_id = ?",
            documentId);

        String filePath = (String) doc.get("file_path");
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        String currentHash = computeSha256Hex(fileBytes);

        Map<String, Object> sigRow = jdbcTemplate.queryForMap(
            "SELECT signature_value, public_key, signer_id, signature_hash FROM digital_signature WHERE document_id = ? ORDER BY signed_at DESC LIMIT 1",
            documentId);

        String originalHash = String.valueOf(doc.get("file_hash_original"));
        if (originalHash == null || originalHash.isBlank() || "null".equalsIgnoreCase(originalHash)) {
            // Backward compatibility for older rows that have null file_hash_original.
            originalHash = String.valueOf(sigRow.get("signature_hash"));
        }
        boolean hashMatches = currentHash.equalsIgnoreCase(originalHash);

        boolean signatureValid = verifySignature(fileBytes, (String) sigRow.get("signature_value"), (String) sigRow.get("public_key"));
        String outcome = "FAILED";
        if (signatureValid && hashMatches) {
            outcome = "AUTHENTIC";
        } else if (!hashMatches) {
            outcome = "TAMPERED";
        }

        String remarks = hashMatches
            ? (signatureValid ? "Document is authentic and unchanged." : "Signature validation failed.")
            : "Document hash changed, indicating tampering or data drift.";

        String verificationId = "VER-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        Timestamp now = new Timestamp(System.currentTimeMillis());
        jdbcTemplate.update(
            "INSERT INTO verification_log (verification_id, document_id, verifier_id, outcome, checked_at, remarks) VALUES (?, ?, ?, ?, ?, ?)",
            verificationId, documentId, verifierId, outcome, now, remarks);
        logAudit("Verification " + outcome, "Verification for document " + documentId + " produced outcome " + outcome, verifierId);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("documentId", documentId);
        result.put("outcome", outcome);
        result.put("verifiedBy", verifierId);
        result.put("timestamp", now.toString());
        result.put("remarks", remarks);
        result.put("hash", currentHash);
        result.put("hashMatches", hashMatches);
        result.put("signatureValid", signatureValid);
        result.put("signerId", sigRow.get("signer_id"));
        return result;
    }

    public Map<String, Object> getDocumentResult(String documentId) throws Exception {
        try {
            return jdbcTemplate.queryForMap(
                "SELECT d.document_id AS documentId, vl.outcome AS outcome, vl.verifier_id AS verifiedBy, vl.checked_at AS timestamp, vl.remarks AS remarks, d.file_name AS docName " +
                "FROM verification_log vl JOIN document d ON vl.document_id = d.document_id WHERE vl.document_id = ? ORDER BY vl.checked_at DESC LIMIT 1",
                documentId);
        } catch (org.springframework.dao.EmptyResultDataAccessException ex) {
            Map<String, Object> fallback = new LinkedHashMap<>();
            fallback.put("documentId", documentId);
            fallback.put("outcome", "FAILED");
            fallback.put("verifiedBy", "system");
            fallback.put("timestamp", new Timestamp(System.currentTimeMillis()).toString());
            fallback.put("remarks", "No verification result found yet.");
            return fallback;
        }
    }

    public List<Map<String, Object>> listSignedDocuments(String userId) {
        return jdbcTemplate.queryForList(
            "SELECT document_id, file_name AS filename, file_path, upload_date AS uploaded_at, document_status FROM document WHERE user_id = ? AND document_status = 'SIGNED' ORDER BY upload_date DESC",
            userId);
    }

    public Map<String, Object> getDashboardSummary() {
        Integer totalUsers = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM \"user\"", Integer.class);
        Integer activeUsers = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM \"user\" WHERE status = 'Active'", Integer.class);
        Integer pendingDocuments = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM document WHERE document_status <> 'SIGNED'", Integer.class);
        Integer failedVerifications = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM verification_log WHERE outcome IN ('FAILED','TAMPERED')", Integer.class);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalUsers", totalUsers != null ? totalUsers : 0);
        summary.put("activeSessions", activeUsers != null ? activeUsers : 0);
        summary.put("pendingAlerts", (pendingDocuments != null ? pendingDocuments : 0) + (failedVerifications != null ? failedVerifications : 0));
        return summary;
    }

    public List<Map<String, Object>> getVerificationHistory(String documentIdFilter) {
        StringBuilder sql = new StringBuilder("SELECT v.verification_id, v.document_id, d.file_name, v.outcome, v.checked_at, v.remarks, v.verifier_id FROM verification_log v JOIN document d ON v.document_id = d.document_id WHERE 1=1");
        if (documentIdFilter != null && !documentIdFilter.isBlank()) {
            sql.append(" AND v.document_id = ?");
            return jdbcTemplate.queryForList(sql.toString(), documentIdFilter);
        }
        sql.append(" ORDER BY v.checked_at DESC");
        return jdbcTemplate.queryForList(sql.toString());
    }

    public List<Map<String, Object>> getAuditTrail() {
        return jdbcTemplate.queryForList("SELECT audit_id, event_type, description, actor_id, created_at FROM audit_trail ORDER BY created_at DESC LIMIT 100");
    }

    public List<Map<String, Object>> listUsers() {
        return jdbcTemplate.queryForList("SELECT u.user_id, u.first_name, u.last_name, u.email, u.role_id, r.role_name, u.status, u.created_at FROM \"user\" u JOIN role r ON u.role_id = r.role_id ORDER BY u.created_at DESC");
    }

    public Map<String, Object> createUser(String firstName, String lastName, String email, String password, String roleId) {
        String userId = "USR-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        String encoded = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode(password);
        jdbcTemplate.update(
            "INSERT INTO \"user\" (user_id, first_name, last_name, email, password, role_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'Active', NOW())",
            userId, firstName, lastName, email, encoded, roleId);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("userId", userId);
        result.put("email", email);
        result.put("roleId", roleId);
        return result;
    }

    public void updateUser(String userId, String firstName, String lastName, String email, String roleId, String status) {
        jdbcTemplate.update(
            "UPDATE \"user\" SET first_name = ?, last_name = ?, email = ?, role_id = ?, status = ? WHERE user_id = ?",
            firstName, lastName, email, roleId, status, userId);
    }

    public List<Map<String, Object>> listKeys() {
        return jdbcTemplate.queryForList("SELECT key_id, user_id, key_type, status, created_at FROM signing_key ORDER BY created_at DESC");
    }

    public Map<String, Object> generateKey(String userId) {
        return signingKeyService.getOrCreateActiveKey(userId);
    }

    public void revokeKey(String keyId) {
        jdbcTemplate.update("UPDATE signing_key SET status = 'Revoked' WHERE key_id = ?", keyId);
    }

    public static boolean verifySignature(byte[] payload, String signatureB64, String publicKeyB64) throws Exception {
        if (payload == null || signatureB64 == null || publicKeyB64 == null) {
            return false;
        }

        byte[] signatureBytes = Base64.getDecoder().decode(signatureB64);
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyB64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = factory.generatePublic(spec);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(payload);
        return verifier.verify(signatureBytes);
    }

    public String computeSha256Hex(byte[] bytes) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(digest.digest(bytes));
    }

    private void ensureSchemaExists() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS document (
                    document_id VARCHAR(64) PRIMARY KEY,
                    file_name VARCHAR(255) NOT NULL,
                    file_path TEXT NOT NULL,
                    user_id VARCHAR(64) NOT NULL,
                    document_status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
                    upload_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    file_size BIGINT NOT NULL DEFAULT 0,
                    file_hash_original TEXT
                )
                """);
        ensureColumnExists("document", "file_name", "VARCHAR(255)");
        ensureColumnExists("document", "file_path", "TEXT");
        ensureColumnExists("document", "user_id", "VARCHAR(64)");
        ensureColumnExists("document", "document_status", "VARCHAR(32)");
        ensureColumnExists("document", "upload_date", "TIMESTAMP");
        ensureColumnExists("document", "file_size", "BIGINT");
        ensureColumnExists("document", "file_hash_original", "TEXT");
        // Backfill legacy rows so signed documents have a baseline hash for verification.
        jdbcTemplate.update("""
                UPDATE document d
                SET file_hash_original = ds.signature_hash
                FROM (
                    SELECT document_id, signature_hash
                    FROM digital_signature
                ) ds
                WHERE d.document_id = ds.document_id
                  AND (d.file_hash_original IS NULL OR TRIM(d.file_hash_original) = '')
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
                    signature_hash TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    signature_value TEXT NOT NULL,
                    signed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    key_id VARCHAR(64) NOT NULL
                )
                """);
        ensureColumnExists("digital_signature", "signature_hash", "TEXT");
        ensureColumnExists("digital_signature", "public_key", "TEXT");
        ensureColumnExists("digital_signature", "signature_value", "TEXT");
        ensureColumnExists("digital_signature", "signed_at", "TIMESTAMP");
        ensureColumnExists("digital_signature", "key_id", "VARCHAR(64)");

        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS audit_trail (
                    audit_id BIGSERIAL PRIMARY KEY,
                    event_type VARCHAR(128) NOT NULL,
                    description TEXT NOT NULL,
                    actor_id VARCHAR(64) NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """);

        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS verification_log (
                    verification_id VARCHAR(64) PRIMARY KEY,
                    document_id VARCHAR(64) NOT NULL,
                    verifier_id VARCHAR(64) NOT NULL,
                    outcome VARCHAR(32) NOT NULL,
                    checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    remarks TEXT NOT NULL
                )
                """);
        ensureColumnExists("verification_log", "document_id", "VARCHAR(64)");
        ensureColumnExists("verification_log", "verifier_id", "VARCHAR(64)");
        ensureColumnExists("verification_log", "outcome", "VARCHAR(32)");
        ensureColumnExists("verification_log", "checked_at", "TIMESTAMP");
        ensureColumnExists("verification_log", "remarks", "TEXT");
    }

    private void ensureColumnExists(String tableName, String columnName, String columnType) {
        Integer count = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = ? AND column_name = ?",
            Integer.class,
            tableName,
            columnName);
        if (count != null && count > 0) {
            return;
        }
        jdbcTemplate.execute("ALTER TABLE " + tableName + " ADD COLUMN IF NOT EXISTS " + columnName + " " + columnType);
    }

    private void logAudit(String eventType, String description, String actorId) {
        jdbcTemplate.update(
            "INSERT INTO audit_trail (event_type, description, actor_id, created_at) VALUES (?, ?, ?, NOW())",
            eventType,
            description,
            actorId);
    }

    private PrivateKey loadPrivateKey(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }
}