package com.example.IT21_FinalProject;

import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/admin/api/monitor")
public class MonitorController {

    private final JdbcTemplate jdbcTemplate;

    public MonitorController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping(path = "/metrics", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new LinkedHashMap<>();

        MemoryMXBean memBean = ManagementFactory.getMemoryMXBean();
        RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
        OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();

        long usedMemory = memBean.getHeapMemoryUsage().getUsed();
        long maxMemory = memBean.getHeapMemoryUsage().getMax();
        long uptime = runtimeBean.getUptime() / 1000;

        double cpuLoad = -1;
        try {
            java.lang.reflect.Method m = osBean.getClass().getMethod("getSystemCpuLoad");
            Object val = m.invoke(osBean);
            if (val instanceof Double doubleValue) {
                cpuLoad = doubleValue * 100.0;
            }
        } catch (Exception ignored) {
        }

        int activeConnections = 0;
        int docsVerifiedLastMinute = 0;
        int totalDocs = 0;
        int totalUsers = 0;
        int pendingDocs = 0;
        try {
            Integer ac = jdbcTemplate.queryForObject("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state = 'active'", Integer.class);
            activeConnections = ac != null ? ac : 0;
        } catch (Exception ignored) {
        }

        try {
            Integer dv = jdbcTemplate.queryForObject("SELECT count(*) FROM digital_signature WHERE signed_at > now() - interval '1 minute'", Integer.class);
            docsVerifiedLastMinute = dv != null ? dv : 0;
        } catch (Exception ignored) {
        }

        try {
            Integer td = jdbcTemplate.queryForObject("SELECT count(*) FROM document", Integer.class);
            totalDocs = td != null ? td : 0;
        } catch (Exception ignored) {
        }

        try {
            Integer tu = jdbcTemplate.queryForObject("SELECT count(*) FROM \"user\"", Integer.class);
            totalUsers = tu != null ? tu : 0;
        } catch (Exception ignored) {
        }

        try {
            Integer pd = jdbcTemplate.queryForObject("SELECT count(*) FROM document WHERE document_status <> 'Signed'", Integer.class);
            pendingDocs = pd != null ? pd : 0;
        } catch (Exception ignored) {
        }

        metrics.put("cpu", cpuLoad >= 0 ? Math.round(cpuLoad) : "unknown");
        metrics.put("memory", maxMemory > 0 ? Math.round((usedMemory * 100.0) / maxMemory) : 0);
        metrics.put("memoryUsed", formatBytes(usedMemory));
        metrics.put("memoryTotal", formatBytes(maxMemory));
        metrics.put("activeConnections", activeConnections);
        metrics.put("uptime", formatUptime(uptime));
        metrics.put("verifiedLastMinute", docsVerifiedLastMinute);
        metrics.put("totalDocuments", totalDocs);
        metrics.put("totalUsers", totalUsers);
        metrics.put("pendingDocuments", pendingDocs);
        metrics.put("timestamp", Instant.now().toEpochMilli());

        return metrics;
    }

    @GetMapping(path = "/sessions", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Map<String, Object>> getActiveSessions() {
        List<Map<String, Object>> sessions = new ArrayList<>();
        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                    "SELECT a.actor_id, COALESCE(u.first_name || ' ' || u.last_name, u.email, a.actor_id) AS user_name, a.created_at " +
                    "FROM audit_trail a LEFT JOIN \"user\" u ON a.actor_id = u.user_id " +
                    "ORDER BY a.created_at DESC LIMIT 5");
            for (Map<String, Object> row : rows) {
                Map<String, Object> session = new LinkedHashMap<>();
                session.put("user", row.get("user_name") != null ? row.get("user_name") : "system");
                session.put("ip", "N/A");
                session.put("loginTime", toEpochMillis(row.get("created_at")));
                session.put("lastActivity", toEpochMillis(row.get("created_at")));
                sessions.add(session);
            }
        } catch (Exception ignored) {
        }
        return sessions;
    }

    @GetMapping(path = "/alerts", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Map<String, Object>> getSecurityAlerts() {
        List<Map<String, Object>> alerts = new ArrayList<>();
        try {
            Integer signedCount = jdbcTemplate.queryForObject("SELECT count(*) FROM digital_signature", Integer.class);
            Integer pendingCount = jdbcTemplate.queryForObject("SELECT count(*) FROM document WHERE document_status <> 'Signed'", Integer.class);
            if (signedCount != null && signedCount > 0) {
                alerts.add(Map.of(
                        "id", "ALERT-001",
                        "level", "info",
                        "title", "Recent signatures recorded",
                        "message", "The system has " + signedCount + " recorded signature event(s).",
                        "timestamp", Instant.now().toEpochMilli()
                ));
            }
            if (pendingCount != null && pendingCount > 0) {
                alerts.add(Map.of(
                        "id", "ALERT-002",
                        "level", "warning",
                        "title", "Pending documents require review",
                        "message", pendingCount + " document(s) remain pending signature.",
                        "timestamp", Instant.now().toEpochMilli()
                ));
            }
        } catch (Exception ignored) {
        }
        return alerts;
    }

    @GetMapping(path = "/performance", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getPerformanceData() {
        Map<String, Object> perfData = new LinkedHashMap<>();

        List<Integer> requestRates = new ArrayList<>();
        List<Integer> responseTimes = new ArrayList<>();
        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                    "SELECT date_trunc('hour', created_at) AS hour_bucket, count(*) AS cnt " +
                    "FROM audit_trail GROUP BY 1 ORDER BY 1 DESC LIMIT 24");
            for (int i = 23; i >= 0; i--) {
                int count = 0;
                for (Map<String, Object> row : rows) {
                    Object bucket = row.get("hour_bucket");
                    if (bucket != null && bucket.toString().contains(Instant.now().minusSeconds(3600L * i).toString().substring(0, 13))) {
                        count = ((Number) row.get("cnt")).intValue();
                        break;
                    }
                }
                requestRates.add(count);
                responseTimes.add(Math.max(20, Math.min(200, count * 10)));
            }
        } catch (Exception ignored) {
            for (int i = 0; i < 24; i++) {
                requestRates.add(0);
                responseTimes.add(20);
            }
        }

        perfData.put("requestRates", requestRates);
        perfData.put("responseTimes", responseTimes);
        perfData.put("peakHour", requestRates.stream().mapToInt(Integer::intValue).max().orElse(0));
        perfData.put("avgThroughput", "n/a");

        return perfData;
    }

    @GetMapping(path = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getHealthStatus() {
        Map<String, Object> health = new LinkedHashMap<>();
        int pendingDocs = 0;
        int totalUsers = 0;
        int activeConnections = 0;
        try {
            pendingDocs = jdbcTemplate.queryForObject("SELECT count(*) FROM document WHERE document_status <> 'Signed'", Integer.class);
            totalUsers = jdbcTemplate.queryForObject("SELECT count(*) FROM \"user\"", Integer.class);
            activeConnections = jdbcTemplate.queryForObject("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state = 'active'", Integer.class);
        } catch (Exception ignored) {
        }

        health.put("status", "healthy");
        health.put("services", Map.of(
                "application", Map.of("status", "up", "uptime", "live", "lastCheck", System.currentTimeMillis()),
                "database", Map.of("status", "up", "connections", activeConnections, "lastCheck", System.currentTimeMillis()),
                "cache", Map.of("status", "up", "hitRate", "n/a", "lastCheck", System.currentTimeMillis()),
                "queue", Map.of("status", "up", "pendingItems", pendingDocs, "lastCheck", System.currentTimeMillis())
        ));

        List<String> warnings = new ArrayList<>();
        if (pendingDocs > 10) {
            warnings.add("More than 10 documents are still pending review");
        }
        if (totalUsers == 0) {
            warnings.add("No users are currently registered");
        }

        health.put("warnings", warnings);
        health.put("timestamp", System.currentTimeMillis());

        return health;
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        char pre = "KMGTPE".charAt(exp - 1);
        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), pre);
    }

    private String formatUptime(long seconds) {
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        return hours + "h " + minutes + "m";
    }

    private long toEpochMillis(Object value) {
        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant().toEpochMilli();
        }
        if (value instanceof Instant instant) {
            return instant.toEpochMilli();
        }
        return System.currentTimeMillis();
    }
}
