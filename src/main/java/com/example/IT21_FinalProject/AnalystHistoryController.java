package com.example.IT21_FinalProject;

import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/analyst/api")
public class AnalystHistoryController {

    private final JdbcTemplate jdbcTemplate;
    private final AtomicLong sequence = new AtomicLong(1000);

    public AnalystHistoryController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping(path = "/verifications", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Map<String, Object>> getVerifications(@RequestParam(defaultValue = "20") int limit,
                                                       @RequestParam(value = "documentId", required = false) String documentId,
                                                       @RequestParam(value = "status", required = false) String status) {
        String sql = "SELECT s.signature_id AS id, d.document_id AS documentId, d.file_name AS docName, COALESCE(u.first_name || ' ' || u.last_name, s.signer_id) AS signer, s.signed_at AS verifiedAt, s.signature_hash AS hash " +
                "FROM digital_signature s JOIN document d ON s.document_id = d.document_id LEFT JOIN \"user\" u ON s.signer_id = u.user_id "+
                "ORDER BY s.signed_at DESC LIMIT ?";

        List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql, limit);

        if (documentId != null && !documentId.isBlank()) {
            String needle = documentId.toUpperCase(Locale.ROOT);
            rows.removeIf(r -> !String.valueOf(r.get("documentid")).toUpperCase(Locale.ROOT).contains(needle));
        }

        if (status != null && !status.isBlank()) {
            // we don't store status explicitly; interpret presence as VALID
            if (!"VALID".equalsIgnoreCase(status)) {
                rows.clear();
            }
        }

        return rows;
    }

    @GetMapping(path = "/verifications/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamVerifications() {
        SseEmitter emitter = new SseEmitter(0L);

        Thread thread = new Thread(() -> {
            try {
                Instant lastSeen = Instant.now();
                for (int i = 0; i < 360; i++) { // ~30 minutes at 5s intervals
                    Timestamp ts = Timestamp.from(lastSeen);
                    List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                            "SELECT s.signature_id AS id, d.document_id AS documentId, d.file_name AS docName, COALESCE(u.first_name || ' ' || u.last_name, s.signer_id) AS signer, s.signed_at AS verifiedAt, s.signature_hash AS hash " +
                                    "FROM digital_signature s JOIN document d ON s.document_id = d.document_id LEFT JOIN \"user\" u ON s.signer_id = u.user_id " +
                                    "WHERE s.signed_at > ? ORDER BY s.signed_at ASC", ts);

                    for (Map<String, Object> r : rows) {
                        emitter.send(SseEmitter.event().name("message").data(r));
                        Object v = r.get("verifiedat");
                        if (v instanceof Timestamp) {
                            lastSeen = ((Timestamp) v).toInstant();
                        }
                    }

                    Thread.sleep(5000);
                }
                emitter.complete();
            } catch (Exception ex) {
                emitter.completeWithError(ex);
            }
        });
        thread.setDaemon(true);
        thread.start();
        return emitter;
    }
}
