package com.example.IT21_FinalProject;

import jakarta.servlet.http.HttpSession;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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
            String currentUserName = jdbcTemplate.queryForObject(
                    "SELECT COALESCE(first_name || ' ' || last_name, email, user_id) FROM \"user\" WHERE user_id = ?",
                    String.class,
                    currentUserId);

            Map<String, Object> row = jdbcTemplate.queryForMap(
                    "SELECT d.file_name, s.signature_id, s.signature_hash, s.public_key, s.signed_at, s.key_id, s.signer_id " +
                    "FROM digital_signature s JOIN document d ON s.document_id = d.document_id " +
                    "WHERE s.document_id = ? ORDER BY s.signed_at DESC LIMIT 1",
                    documentId);

            Map<String, Object> result = Map.of(
                    "docName", row.get("file_name"),
                    "signatureId", row.get("signature_id"),
                    "hash", row.get("signature_hash"),
                    "publicKey", row.get("public_key"),
                    "signedAt", row.get("signed_at"),
                    "keyId", row.get("key_id"),
                    "signerId", row.get("signer_id"),
                    "signerName", currentUserName
            );
            return ResponseEntity.ok(result);
        } catch (org.springframework.dao.EmptyResultDataAccessException e) {
            return ResponseEntity.status(404).body(Map.of("message", "Result not found."));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Failed to load result: " + e.getMessage()));
        }
    }
}