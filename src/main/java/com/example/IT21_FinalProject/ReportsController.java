package com.example.IT21_FinalProject;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/admin/api/reports")
public class ReportsController {

    private final JdbcTemplate jdbcTemplate;

    public ReportsController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/stats")
    public Map<String, Object> getStats(
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate) {

        Map<String, Object> stats = new LinkedHashMap<>();
        try {
            Integer totalDocs = jdbcTemplate.queryForObject("SELECT count(*) FROM document", Integer.class);
            Integer successful = jdbcTemplate.queryForObject("SELECT count(*) FROM digital_signature", Integer.class);
            Integer totalUsers = jdbcTemplate.queryForObject("SELECT count(*) FROM \"user\"", Integer.class);
            Integer pendingDocs = jdbcTemplate.queryForObject("SELECT count(*) FROM document WHERE document_status <> 'Signed'", Integer.class);
            Integer auditEvents = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_trail", Integer.class);

            stats.put("documentsVerified", totalDocs != null ? totalDocs : 0);
            stats.put("successfulVerifications", successful != null ? successful : 0);
            stats.put("failedVerifications", 0);
            stats.put("averageVerificationTime", "n/a");
            stats.put("successRate", successful != null && totalDocs != null && totalDocs > 0 ? Math.round((successful * 100.0) / totalDocs) + "%" : "0%");
            stats.put("totalUsers", totalUsers != null ? totalUsers : 0);
            stats.put("activeToday", auditEvents != null ? auditEvents : 0);
            stats.put("securityEvents", pendingDocs != null ? pendingDocs : 0);
        } catch (Exception e) {
            stats.put("error", e.getMessage());
        }

        stats.put("period", (startDate != null ? startDate : "all") + " to " + (endDate != null ? endDate : "today"));
        return stats;
    }

    @GetMapping("/generate")
    public Map<String, Object> generateReport(
            @RequestParam(defaultValue = "daily") String template,
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate) {

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("title", capitalize(template) + " Report");
        report.put("generatedAt", Instant.now().toString());
        report.put("template", template);
        report.put("startDate", startDate != null ? startDate : LocalDate.now().toString());
        report.put("endDate", endDate != null ? endDate : LocalDate.now().toString());

        Map<String, Object> stats = new LinkedHashMap<>();
        try {
            Integer successful = jdbcTemplate.queryForObject("SELECT count(*) FROM digital_signature", Integer.class);
            Integer totalDocs = jdbcTemplate.queryForObject("SELECT count(*) FROM document", Integer.class);
            Integer totalUsers = jdbcTemplate.queryForObject("SELECT count(*) FROM \"user\"", Integer.class);
            Integer auditEvents = jdbcTemplate.queryForObject("SELECT count(*) FROM audit_trail", Integer.class);
            Integer pendingDocs = jdbcTemplate.queryForObject("SELECT count(*) FROM document WHERE document_status <> 'Signed'", Integer.class);

            stats.put("verifications", successful != null ? successful : 0);
            stats.put("successful", successful != null ? successful : 0);
            stats.put("failed", 0);
            stats.put("avgTime", "n/a");
            stats.put("users", totalUsers != null ? totalUsers : 0);
            stats.put("documents", totalDocs != null ? totalDocs : 0);
            stats.put("pendingDocuments", pendingDocs != null ? pendingDocs : 0);
            stats.put("auditEvents", auditEvents != null ? auditEvents : 0);
        } catch (Exception ignored) {
            stats.put("verifications", 0);
            stats.put("successful", 0);
            stats.put("failed", 0);
            stats.put("avgTime", "n/a");
            stats.put("users", 0);
            stats.put("documents", 0);
            stats.put("pendingDocuments", 0);
            stats.put("auditEvents", 0);
        }

        switch (template.toLowerCase()) {
            case "daily":
                report.put("summary", "Daily verification and system activity summary");
                report.put("stats", stats);
                report.put("details", buildRecentAuditDetails(4));
                break;
            case "user_activity":
                report.put("summary", "User activity and access patterns");
                report.put("stats", stats);
                report.put("topUsers", fetchTopUsers(3));
                break;
            case "audit":
                report.put("summary", "Comprehensive audit trail and compliance report");
                report.put("stats", stats);
                report.put("events", fetchAuditEvents(4));
                break;
            default:
                report.put("summary", "System report generated from live database records");
                report.put("stats", stats);
                report.put("details", buildRecentAuditDetails(4));
        }

        return report;
    }

    @GetMapping("/export")
    public ResponseEntity<?> exportReport(
            @RequestParam(defaultValue = "csv") String format,
            @RequestParam(defaultValue = "daily") String template,
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate) {

        Map<String, Object> reportData = generateReport(template, startDate, endDate);

        if ("csv".equalsIgnoreCase(format)) {
            String csv = generateCSV(reportData, template);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment;filename=\"report_" + template + "_" + System.currentTimeMillis() + ".csv\"")
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(csv);
        } else if ("pdf".equalsIgnoreCase(format)) {
            String pdf = generatePDFPlaceholder(reportData, template);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment;filename=\"report_" + template + "_" + System.currentTimeMillis() + ".txt\"")
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(pdf);
        }

        return ResponseEntity.badRequest().body("Invalid format");
    }

    private String generateCSV(Map<String, Object> report, String template) {
        StringBuilder csv = new StringBuilder();
        csv.append("Report Type,").append(report.get("title")).append("\n");
        csv.append("Generated At,").append(report.get("generatedAt")).append("\n");
        csv.append("Period,").append(report.get("startDate")).append(" to ").append(report.get("endDate")).append("\n\n");

        if (report.containsKey("stats")) {
            Map<String, Object> stats = (Map<String, Object>) report.get("stats");
            csv.append("Metric,Value\n");
            for (Map.Entry<String, Object> entry : stats.entrySet()) {
                csv.append(entry.getKey()).append(",").append(entry.getValue()).append("\n");
            }
        }

        return csv.toString();
    }

    private String generatePDFPlaceholder(Map<String, Object> report, String template) {
        StringBuilder txt = new StringBuilder();
        txt.append("=== ").append(report.get("title")).append(" ===\n");
        txt.append("Generated: ").append(report.get("generatedAt")).append("\n");
        txt.append("Period: ").append(report.get("startDate")).append(" to ").append(report.get("endDate")).append("\n\n");
        txt.append(report.get("summary")).append("\n\n");
        txt.append("Statistics:\n");

        if (report.containsKey("stats")) {
            Map<String, Object> stats = (Map<String, Object>) report.get("stats");
            for (Map.Entry<String, Object> entry : stats.entrySet()) {
                txt.append("  ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
        }

        return txt.toString();
    }

    private List<String> buildRecentAuditDetails(int limit) {
        List<String> details = new ArrayList<>();
        for (Map<String, Object> row : fetchAuditEvents(limit)) {
            details.add(row.get("time") + " - " + row.get("message"));
        }
        return details;
    }

    private List<Map<String, Object>> fetchAuditEvents(int limit) {
        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                    "SELECT created_at AS time, event_type, description AS message FROM audit_trail ORDER BY created_at DESC LIMIT ?",
                    limit);
            List<Map<String, Object>> events = new ArrayList<>();
            for (Map<String, Object> row : rows) {
                Map<String, Object> event = new LinkedHashMap<>();
                event.put("time", row.get("time"));
                event.put("level", "INFO");
                event.put("message", row.get("message"));
                events.add(event);
            }
            return events;
        } catch (Exception e) {
            return List.of();
        }
    }

    private List<Map<String, Object>> fetchTopUsers(int limit) {
        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                    "SELECT COALESCE(u.first_name || ' ' || u.last_name, u.email, s.signer_id) AS name, COUNT(*) AS activity, COALESCE(u.role_id, 'Staff') AS role " +
                    "FROM digital_signature s LEFT JOIN \"user\" u ON s.signer_id = u.user_id GROUP BY name, role ORDER BY activity DESC LIMIT ?",
                    limit);
            List<Map<String, Object>> topUsers = new ArrayList<>();
            for (Map<String, Object> row : rows) {
                Map<String, Object> user = new LinkedHashMap<>();
                user.put("name", row.get("name"));
                user.put("activity", row.get("activity"));
                user.put("role", row.get("role"));
                topUsers.add(user);
            }
            return topUsers;
        } catch (Exception e) {
            return List.of();
        }
    }

    private String capitalize(String s) {
        return s.substring(0, 1).toUpperCase() + s.substring(1).replaceAll("_", " ");
    }
}
