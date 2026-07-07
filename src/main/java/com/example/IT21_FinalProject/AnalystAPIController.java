package com.example.IT21_FinalProject;

import jakarta.servlet.http.HttpSession;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/analyst/api")
public class AnalystAPIController {

    private final JdbcTemplate jdbcTemplate;
    private final DocumentsSigningService documentsSigningService;

    public AnalystAPIController(JdbcTemplate jdbcTemplate, DocumentsSigningService documentsSigningService) {
        this.jdbcTemplate = jdbcTemplate;
        this.documentsSigningService = documentsSigningService;
    }

    @GetMapping("/verifications")
    public ResponseEntity<?> getVerifications(
            HttpSession session,
            @RequestParam(value = "documentId", required = false) String documentId,
            @RequestParam(value = "status", required = false) String status,
            @RequestParam(value = "limit", defaultValue = "50") int limit) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }

        try {
            String roleId = jdbcTemplate.queryForObject(
                    "SELECT role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
                    String.class, userEmail);
            if (!"ROL004".equals(roleId)) {
                return ResponseEntity.status(403).body(Map.of("message", "Access denied."));
            }

            return ResponseEntity.ok(loadVerificationRecords(documentId, status, limit));
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(401).body(Map.of("message", "User not found."));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Failed to load verifications: " + e.getMessage()));
        }
    }

    @GetMapping(value = "/reports/export", produces = "text/csv")
    public ResponseEntity<String> exportReports(
            HttpSession session,
            @RequestParam(value = "documentId", required = false) String documentId,
            @RequestParam(value = "status", required = false) String status,
            @RequestParam(value = "limit", defaultValue = "50") int limit) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body("Please log in first.");
        }

        try {
            String roleId = jdbcTemplate.queryForObject(
                    "SELECT role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
                    String.class, userEmail);
            if (!"ROL004".equals(roleId)) {
                return ResponseEntity.status(403).body("Access denied.");
            }

            List<Map<String, Object>> records = loadVerificationRecords(documentId, status, limit);
            StringBuilder csv = new StringBuilder();
            csv.append("Verification ID,Record ID,Document ID,Document Name,Signer,Verified By,Verified At,Outcome,Status,RSA Signature,SHA-256 Integrity,Certificate Status,Document Hash,Remarks\n");
            for (Map<String, Object> record : records) {
                csv.append(csvEscape(record.get("verificationId"))).append(',');
                csv.append(csvEscape(record.get("id"))).append(',');
                csv.append(csvEscape(record.get("documentId"))).append(',');
                csv.append(csvEscape(record.get("docName"))).append(',');
                csv.append(csvEscape(record.get("signer"))).append(',');
                csv.append(csvEscape(record.get("verifiedBy"))).append(',');
                csv.append(csvEscape(record.get("verifiedAt"))).append(',');
                csv.append(csvEscape(record.get("outcome"))).append(',');
                csv.append(csvEscape(record.get("status"))).append(',');
                csv.append(csvEscape(boolLabel(record.get("rsaSignatureValid"), "Valid", "Invalid"))).append(',');
                csv.append(csvEscape(boolLabel(record.get("integrityMatch"), "Match", "Mismatch"))).append(',');
                csv.append(csvEscape(boolLabel(record.get("certificateValid"), "Valid", "Invalid"))).append(',');
                csv.append(csvEscape(record.get("hash"))).append(',');
                csv.append(csvEscape(record.get("remarks"))).append('\n');
            }

            String filename = "verification-reports-" + Instant.now().toEpochMilli() + ".csv";
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .contentType(MediaType.parseMediaType("text/csv"))
                    .body(csv.toString());
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(401).body("User not found.");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Failed to export reports: " + e.getMessage());
        }
    }

    private List<Map<String, Object>> loadVerificationRecords(String documentId, String status, int limit) throws Exception {
        StringBuilder sql = new StringBuilder(
                "SELECT vl.verification_id, vl.document_id, vl.outcome, vl.checked_at, vl.remarks, " +
                "d.file_name, d.file_path, ds.signature_id, ds.signature_hash, ds.signature_value, ds.public_key, " +
                "COALESCE(signer_u.first_name || ' ' || signer_u.last_name, ds.signer_id) AS signer, " +
                "COALESCE(analyst_u.first_name || ' ' || analyst_u.last_name, vl.verifier_id) AS verified_by " +
                "FROM verification_log vl " +
                "JOIN document d ON d.document_id = vl.document_id " +
                "JOIN digital_signature ds ON ds.document_id = vl.document_id " +
                "LEFT JOIN \"user\" signer_u ON signer_u.user_id = ds.signer_id " +
                "LEFT JOIN \"user\" analyst_u ON analyst_u.user_id = vl.verifier_id " +
                "WHERE 1=1"
        );

        List<Object> params = new ArrayList<>();
        if (documentId != null && !documentId.trim().isEmpty()) {
            sql.append(" AND (d.document_id ILIKE ? OR d.file_name ILIKE ?)");
            String searchTerm = "%" + documentId.trim() + "%";
            params.add(searchTerm);
            params.add(searchTerm);
        }

        sql.append(" ORDER BY vl.checked_at DESC LIMIT ?");
        params.add(limit);

        List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql.toString(), params.toArray());
        List<Map<String, Object>> results = new ArrayList<>();

        for (Map<String, Object> row : rows) {
            String documentIdVal = (String) row.get("document_id");
            String signatureValue = (String) row.get("signature_value");
            String publicKeyB64 = (String) row.get("public_key");
            boolean rsaValid = false;
            boolean integrityMatch = false;

            try {
                String filePath = (String) row.get("file_path");
                if (filePath != null && Files.exists(Paths.get(filePath))) {
                    byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
                    rsaValid = DocumentsSigningService.verifySignature(
                            fileBytes, signatureValue, publicKeyB64);

                    java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                    byte[] digestBytes = digest.digest(fileBytes);
                    StringBuilder sb = new StringBuilder();
                    for (byte b : digestBytes) sb.append(String.format("%02x", b));
                    String currentHash = sb.toString();
                    String storedHash = String.valueOf(row.get("signature_hash"));
                    integrityMatch = currentHash.equalsIgnoreCase(storedHash);
                }
            } catch (Exception ignored) {
                rsaValid = false;
                integrityMatch = false;
            }

            String outcome = String.valueOf(row.get("outcome"));
            String recordStatus = switch (outcome) {
                case "AUTHENTIC" -> "VALID";
                case "TAMPERED" -> "TAMPERED";
                default -> "INVALID";
            };

            if (status != null && !status.isEmpty() && !recordStatus.equals(status)) {
                continue;
            }

            Map<String, Object> record = new LinkedHashMap<>();
            record.put("id", row.get("signature_id"));
            record.put("verificationId", row.get("verification_id"));
            record.put("documentId", documentIdVal);
            record.put("docName", row.get("file_name"));
            record.put("verifiedAt", row.get("checked_at"));
            record.put("signer", row.get("signer"));
            record.put("verifiedBy", row.get("verified_by"));
            record.put("hash", row.get("signature_hash"));
            record.put("outcome", outcome);
            record.put("remarks", row.get("remarks"));
            record.put("rsaSignatureValid", rsaValid);
            record.put("integrityMatch", integrityMatch);
            record.put("certificateValid", rsaValid && integrityMatch);
            record.put("status", recordStatus);
            results.add(record);
        }

        return results;
    }

    private String csvEscape(Object value) {
        if (value == null) return "\"\"";
        String text = String.valueOf(value).replace("\"", "\"\"");
        return "\"" + text + "\"";
    }

    private String boolLabel(Object value, String yes, String no) {
        if (value == null) return "";
        return Boolean.TRUE.equals(value) ? yes : no;
    }

    @GetMapping("/verifications/stream")
    public void getVerificationsStream(HttpSession session) {
        // This would require Server-Sent Events setup; for now returning 200 OK
        // A full implementation would stream newly-completed verifications
    }

    @PostMapping("/documents/{documentId}/verify")
    public ResponseEntity<?> verifyPendingDocument(@PathVariable String documentId, HttpSession session) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }

        try {
            String roleId = jdbcTemplate.queryForObject(
                    "SELECT role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
                    String.class, userEmail);
            if (!"ROL004".equals(roleId)) {
                return ResponseEntity.status(403).body(Map.of("message", "Access denied."));
            }

            Integer alreadyVerified = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM verification_log WHERE document_id = ?",
                    Integer.class, documentId);
            if (alreadyVerified != null && alreadyVerified > 0) {
                return ResponseEntity.status(409).body(Map.of("message", "This document has already been verified."));
            }

            jdbcTemplate.queryForMap(
                    "SELECT document_id FROM document WHERE document_id = ? AND UPPER(document_status) = 'SIGNED'",
                    documentId);

            String analystId = jdbcTemplate.queryForObject(
                    "SELECT user_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
                    String.class, userEmail);

            Map<String, Object> verification = documentsSigningService.verifyDocument(documentId, analystId);
            String outcome = String.valueOf(verification.get("outcome"));
            boolean rsaValid = Boolean.TRUE.equals(verification.get("signatureValid"));
            boolean integrityMatch = Boolean.TRUE.equals(verification.get("hashMatches"));

            Map<String, Object> sigRow = jdbcTemplate.queryForMap(
                    "SELECT s.signature_id, s.signature_hash, s.signer_id, d.file_name " +
                            "FROM digital_signature s JOIN document d ON s.document_id = d.document_id " +
                            "WHERE s.document_id = ? ORDER BY s.signed_at DESC LIMIT 1",
                    documentId);

            String status = switch (outcome) {
                case "AUTHENTIC" -> "VALID";
                case "TAMPERED" -> "TAMPERED";
                default -> "INVALID";
            };

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", status);
            result.put("outcome", outcome);
            result.put("rsaSignatureValid", rsaValid);
            result.put("integrityMatch", integrityMatch);
            result.put("certificateValid", rsaValid && integrityMatch);
            result.put("signer", sigRow.get("signer_id"));
            result.put("timestamp", verification.get("timestamp"));
            result.put("hash", verification.get("hash"));
            result.put("fileName", sigRow.get("file_name"));
            result.put("signatureId", sigRow.get("signature_id"));
            result.put("documentId", documentId);
            result.put("remarks", verification.get("remarks"));
            return ResponseEntity.ok(result);
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(404).body(Map.of("message", "Document not found or not signed."));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Verification failed: " + e.getMessage()));
        }
    }

    @GetMapping("/pending-reviews")
    public ResponseEntity<?> getPendingReviews(HttpSession session,
                                               @RequestParam(value = "limit", defaultValue = "50") int limit) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }

        try {
            String roleId = jdbcTemplate.queryForObject(
                    "SELECT role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
                    String.class, userEmail);
            if (!"ROL004".equals(roleId)) {
                return ResponseEntity.status(403).body(Map.of("message", "Access denied."));
            }

            List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                    "SELECT d.document_id, d.file_name, d.upload_date, " +
                            "COALESCE(u.first_name || ' ' || u.last_name, d.user_id) AS signer_name " +
                            "FROM document d " +
                            "LEFT JOIN \"user\" u ON d.user_id = u.user_id " +
                            "WHERE UPPER(d.document_status) = 'SIGNED' " +
                            "AND NOT EXISTS (SELECT 1 FROM verification_log vl WHERE vl.document_id = d.document_id) " +
                            "ORDER BY d.upload_date DESC LIMIT ?",
                    limit);
            return ResponseEntity.ok(rows);
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(401).body(Map.of("message", "User not found."));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Failed to load pending reviews: " + e.getMessage()));
        }
    }

    @GetMapping("/dashboard-stats")
    public ResponseEntity<?> getDashboardStats(HttpSession session) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }

        try {
            String roleId = jdbcTemplate.queryForObject(
                    "SELECT role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
                    String.class, userEmail);
            if (!"ROL004".equals(roleId)) {
                return ResponseEntity.status(403).body(Map.of("message", "Access denied."));
            }

            Integer verifiedDocuments = jdbcTemplate.queryForObject(
                    "SELECT COUNT(DISTINCT document_id) FROM verification_log",
                    Integer.class);
            Integer pendingDocuments = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM document d " +
                            "WHERE UPPER(d.document_status) = 'SIGNED' " +
                            "AND NOT EXISTS (SELECT 1 FROM verification_log vl WHERE vl.document_id = d.document_id)",
                    Integer.class);
            Integer recentAlerts = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM verification_log WHERE outcome IN ('FAILED', 'TAMPERED')",
                    Integer.class);

            Map<String, Object> stats = new LinkedHashMap<>();
            stats.put("verifiedDocuments", verifiedDocuments != null ? verifiedDocuments : 0);
            stats.put("pendingDocuments", pendingDocuments != null ? pendingDocuments : 0);
            stats.put("recentAlerts", recentAlerts != null ? recentAlerts : 0);
            return ResponseEntity.ok(stats);
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(401).body(Map.of("message", "User not found."));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Failed to load dashboard stats: " + e.getMessage()));
        }
    }

    @GetMapping("/recent-activity")
    public ResponseEntity<?> getRecentActivity(HttpSession session,
                                               @RequestParam(value = "limit", defaultValue = "10") int limit) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }

        try {
            String roleId = jdbcTemplate.queryForObject(
                    "SELECT role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
                    String.class, userEmail);
            if (!"ROL004".equals(roleId)) {
                return ResponseEntity.status(403).body(Map.of("message", "Access denied."));
            }

            List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                    "SELECT vl.checked_at AS created_at, vl.outcome, d.document_id, d.file_name, " +
                            "COALESCE(u.first_name || ' ' || u.last_name, vl.verifier_id) AS analyst_name " +
                            "FROM verification_log vl " +
                            "JOIN document d ON d.document_id = vl.document_id " +
                            "LEFT JOIN \"user\" u ON u.user_id = vl.verifier_id " +
                            "ORDER BY vl.checked_at DESC LIMIT ?",
                    limit);
            return ResponseEntity.ok(rows);
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(401).body(Map.of("message", "User not found."));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Failed to load recent activity: " + e.getMessage()));
        }
    }
}
