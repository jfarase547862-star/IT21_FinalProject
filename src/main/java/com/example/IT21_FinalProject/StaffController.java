package com.example.IT21_FinalProject;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/admin/api/staff")
public class StaffController {

    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

    private final JdbcTemplate jdbcTemplate;

    public StaffController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping(path = "/verify", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Map<String, Object> verifyDocument(@RequestParam("file") MultipartFile file,
                                              @RequestParam(value = "notes", required = false) String notes) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (file == null || file.isEmpty()) {
            result.put("error", "No file uploaded");
            return result;
        }

        try {
            byte[] bytes = file.getBytes();
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            String hash = sb.toString();

            try {
                Map<String, Object> row = jdbcTemplate.queryForMap(
                        "SELECT s.signature_id, s.signature_hash, s.signed_at, s.key_id, s.signer_id, d.file_name FROM digital_signature s JOIN document d ON s.document_id = d.document_id WHERE s.signature_hash = ? ORDER BY s.signed_at DESC LIMIT 1",
                        hash);

                result.put("documentName", row.get("file_name"));
                result.put("uploadedAt", DATE_FORMAT.format(Instant.now()));
                result.put("status", "Verified");
                result.put("confidence", "100%");
                result.put("verificationId", row.get("signature_id"));
                result.put("notes", notes != null ? notes : "Verified from database record");
                result.put("reportAvailable", true);
                result.put("downloadReportUrl", "/admin/api/staff/report?docId=" + row.get("signature_id") + "&format=csv");
                return result;
            } catch (EmptyResultDataAccessException ex) {
                result.put("documentName", file.getOriginalFilename());
                result.put("uploadedAt", DATE_FORMAT.format(Instant.now()));
                result.put("status", "NotFound");
                result.put("confidence", "0%");
                result.put("verificationId", "N/A");
                result.put("notes", notes != null ? notes : "No matching signature found in database.");
                result.put("reportAvailable", false);
                return result;
            }

        } catch (Exception e) {
            result.put("error", e.getMessage());
            return result;
        }
    }

    @GetMapping(path = "/history", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Map<String, Object>> getHistory(@RequestParam(value = "startDate", required = false) String startDate,
                                                @RequestParam(value = "endDate", required = false) String endDate) {
        List<Map<String, Object>> history = new ArrayList<>();
        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                    "SELECT s.signature_id AS verificationId, d.file_name AS documentName, s.signed_at AS verifiedAt, COALESCE(u.first_name || ' ' || u.last_name, s.signer_id) AS signer " +
                            "FROM digital_signature s JOIN document d ON s.document_id = d.document_id LEFT JOIN \"user\" u ON s.signer_id = u.user_id ORDER BY s.signed_at DESC LIMIT 50");

            for (Map<String, Object> r : rows) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("verificationId", r.get("verificationid"));
                item.put("documentName", r.get("documentname"));
                Object v = r.get("verifiedat");
                if (v instanceof Timestamp timestamp) {
                    item.put("verifiedAt", DATE_FORMAT.format(timestamp.toInstant()));
                } else {
                    item.put("verifiedAt", String.valueOf(r.get("verifiedat")));
                }
                item.put("signer", r.get("signer"));
                item.put("status", "Verified");
                item.put("confidence", "100%");
                item.put("reportUrl", "/admin/api/staff/report?docId=" + r.get("verificationid") + "&format=csv");
                history.add(item);
            }
        } catch (Exception ignored) {
        }
        return history;
    }

    @GetMapping(path = "/report")
    public ResponseEntity<String> downloadReport(@RequestParam("docId") String docId,
                                                 @RequestParam(value = "format", defaultValue = "csv") String format) {
        Map<String, Object> record = findVerificationRecord(docId);
        String title = "Verification Report for " + docId;
        String payload;
        String filename = "verification-report-" + docId + "." + format;

        if (record == null) {
            payload = "No verification record found for " + docId + "\n";
        } else if ("pdf".equalsIgnoreCase(format)) {
            payload = "Verification Report\n";
            payload += "Generated At, " + DATE_FORMAT.format(Instant.now()) + "\n";
            payload += "Verification ID, " + record.get("signature_id") + "\n";
            payload += "Document, " + record.get("file_name") + "\n";
            payload += "Signer, " + record.get("signer") + "\n";
            payload += "Signed At, " + record.get("signed_at") + "\n";
            payload += "Status, Verified\n";
        } else {
            payload = "Report Title, " + title + "\n";
            payload += "Generated At, " + DATE_FORMAT.format(Instant.now()) + "\n";
            payload += "Verification ID, " + record.get("signature_id") + "\n";
            payload += "Document, " + record.get("file_name") + "\n";
            payload += "Signer, " + record.get("signer") + "\n";
            payload += "Signed At, " + record.get("signed_at") + "\n";
            payload += "Status, Verified\n";
            payload += "Confidence, 100%\n";
        }

        MediaType mediaType = "pdf".equalsIgnoreCase(format) ? MediaType.APPLICATION_PDF : MediaType.TEXT_PLAIN;
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=\"" + filename + "\"")
                .contentType(mediaType)
                .body(payload);
    }

    private Map<String, Object> findVerificationRecord(String docId) {
        try {
            return jdbcTemplate.queryForMap(
                    "SELECT s.signature_id, d.file_name, s.signed_at, COALESCE(u.first_name || ' ' || u.last_name, u.email, s.signer_id) AS signer " +
                    "FROM digital_signature s JOIN document d ON s.document_id = d.document_id LEFT JOIN \"user\" u ON s.signer_id = u.user_id " +
                    "WHERE s.signature_id = ?",
                    docId);
        } catch (EmptyResultDataAccessException ex) {
            return null;
        }
    }
}
