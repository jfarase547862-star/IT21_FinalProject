package com.example.IT21_FinalProject;

import jakarta.servlet.http.HttpSession;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/signer/api")
public class SignerAPIController {

    private final DocumentsSigningService signingService;
    private final JdbcTemplate jdbcTemplate;

    public SignerAPIController(DocumentsSigningService signingService, JdbcTemplate jdbcTemplate) {
        this.signingService = signingService;
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/documents/pending")
    public ResponseEntity<?> pendingDocuments(HttpSession session) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }

        String userId;
        try {
            userId = jdbcTemplate.queryForObject("SELECT user_id FROM \"user\" WHERE email = ?", String.class, userEmail);
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(401).body(Map.of("message", "User not found."));
        }

        List<Map<String, Object>> pending = signingService.getPendingDocuments(userId);
        return ResponseEntity.ok(pending);
    }

    @PostMapping(value = "/documents/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file, HttpSession session) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }

        try {
            String userId = jdbcTemplate.queryForObject("SELECT user_id FROM \"user\" WHERE email = ?", String.class, userEmail);
            Map<String, Object> result = signingService.uploadDocument(file, userId);
            return ResponseEntity.ok(result);
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(401).body(Map.of("message", "User not found."));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Upload failed: " + e.getMessage()));
        }
    }

    @PostMapping("/documents/{id}/sign")
    public ResponseEntity<?> sign(@PathVariable("id") String documentId, HttpSession session) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }

        try {
            String userId = jdbcTemplate.queryForObject("SELECT user_id FROM \"user\" WHERE email = ?", String.class, userEmail);
            Map<String, Object> result = signingService.signDocument(documentId, userId);
            return ResponseEntity.ok(result);

        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(404).body(Map.of("message", "Document not found."));
        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(Map.of("message", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(409).body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Signing failed: " + e.getMessage()));
        }
    }

    @GetMapping("/documents/{id}/result")
    public ResponseEntity<?> documentResult(@PathVariable("id") String documentId, HttpSession session) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }

        try {
            String currentUserId = jdbcTemplate.queryForObject(
                    "SELECT user_id FROM \"user\" WHERE email = ?",
                    String.class,
                    userEmail);

            Map<String, Object> ownerCheck = jdbcTemplate.queryForMap(
                    "SELECT user_id FROM document WHERE document_id = ?", documentId);
            if (!currentUserId.equals(ownerCheck.get("user_id"))) {
                return ResponseEntity.status(403).body(Map.of("message", "You do not own this document."));
            }

            Integer verificationCount = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM verification_log WHERE document_id = ?",
                    Integer.class,
                    documentId);
            if (verificationCount == null || verificationCount == 0) {
                return ResponseEntity.status(404).body(Map.of(
                        "message", "This document has not been verified by a security analyst yet."));
            }

            Map<String, Object> verification = signingService.getDocumentResult(documentId);
            String currentUserName = jdbcTemplate.queryForObject(
                    "SELECT COALESCE(first_name || ' ' || last_name, email, user_id) FROM \"user\" WHERE user_id = ?",
                    String.class,
                    currentUserId);

            Map<String, Object> row = jdbcTemplate.queryForMap(
                    "SELECT d.file_name, d.file_path, s.signature_id, s.signature_hash, s.public_key, s.signature_value, s.signed_at, s.key_id, s.signer_id " +
                    "FROM digital_signature s JOIN document d ON s.document_id = d.document_id " +
                    "WHERE s.document_id = ? ORDER BY s.signed_at DESC LIMIT 1",
                    documentId);

            boolean rsaSignatureValid = false;
            boolean integrityMatch = false;
            try {
                String filePath = (String) row.get("file_path");
                if (filePath != null && Files.exists(Paths.get(filePath))) {
                    byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
                    rsaSignatureValid = DocumentsSigningService.verifySignature(
                            fileBytes,
                            (String) row.get("signature_value"),
                            (String) row.get("public_key"));

                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] digestBytes = digest.digest(fileBytes);
                    StringBuilder sb = new StringBuilder();
                    for (byte b : digestBytes) {
                        sb.append(String.format("%02x", b));
                    }
                    String currentHash = sb.toString();
                    String storedHash = String.valueOf(row.get("signature_hash"));
                    integrityMatch = currentHash.equalsIgnoreCase(storedHash);
                }
            } catch (Exception ignored) {
                rsaSignatureValid = false;
                integrityMatch = false;
            }

            String outcome = String.valueOf(verification.get("outcome"));
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("docName", row.get("file_name"));
            result.put("signatureId", row.get("signature_id"));
            result.put("hash", row.get("signature_hash"));
            result.put("publicKey", row.get("public_key"));
            result.put("signedAt", verification.get("timestamp"));
            result.put("keyId", row.get("key_id"));
            result.put("signerId", row.get("signer_id"));
            result.put("signerName", currentUserName);
            result.put("verifiedBy", verification.get("verifiedBy"));
            result.put("outcome", outcome);
            result.put("remarks", verification.get("remarks"));
            result.put("rsaSignatureValid", rsaSignatureValid);
            result.put("integrityMatch", integrityMatch);
            result.put("certificateValid", "AUTHENTIC".equals(outcome));
            return ResponseEntity.ok(result);
        } catch (org.springframework.dao.EmptyResultDataAccessException e) {
            return ResponseEntity.status(404).body(Map.of("message", "Result not found."));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Failed to load result: " + e.getMessage()));
        }
    }
}