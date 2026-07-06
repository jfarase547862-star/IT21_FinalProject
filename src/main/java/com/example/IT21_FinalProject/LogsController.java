package com.example.IT21_FinalProject;

import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class LogsController {

    private final JdbcTemplate jdbcTemplate;

    public LogsController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    private static final File[] POSSIBLE_LOG_FILES = new File[] {
            new File("logs/application.log"),
            new File("application.log"),
            new File("logs/app.log")
    };

    private File findLogFile() {
        for (File f : POSSIBLE_LOG_FILES) {
            if (f.exists() && f.isFile()) return f;
        }
        return null;
    }

    @GetMapping(path = "/admin/api/logs", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<String> getRecentLogs(@RequestParam(name = "lines", defaultValue = "200") int lines) {
        File log = findLogFile();
        if (log != null) {
            try {
                return readLastLines(log, lines);
            } catch (IOException e) {
                return Collections.singletonList("Error reading log: " + e.getMessage());
            }
        }
        return readAuditTrailLogs(lines);
    }

    @GetMapping(path = "/admin/api/logs/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamLogs() {
        SseEmitter emitter = new SseEmitter(0L);

        new Thread(() -> {
            File log = findLogFile();
            if (log == null) {
                try {
                    for (String s : readAuditTrailLogs(50)) {
                        emitter.send(SseEmitter.event().name("message").data(s));
                        Thread.sleep(200);
                    }
                    emitter.complete();
                } catch (Exception ex) {
                    emitter.completeWithError(ex);
                }
                return;
            }

            long lastLen = 0;
            try (RandomAccessFile raf = new RandomAccessFile(log, "r")) {
                lastLen = raf.length();
            } catch (IOException ignored) {
            }

            Instant start = Instant.now();
            while (Duration.between(start, Instant.now()).toMinutes() < 60) {
                try {
                    long fileLen = log.length();
                    if (fileLen > lastLen) {
                        try (RandomAccessFile raf = new RandomAccessFile(log, "r")) {
                            raf.seek(lastLen);
                            String line;
                            while ((line = raf.readLine()) != null) {
                                String decoded = new String(line.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
                                emitter.send(SseEmitter.event().name("message").data(decoded));
                            }
                            lastLen = raf.getFilePointer();
                        }
                    }
                    Thread.sleep(1000);
                } catch (Exception e) {
                    emitter.completeWithError(e);
                    return;
                }
            }
            emitter.complete();
        }).start();

        return emitter;
    }

    private List<String> readAuditTrailLogs(int lines) {
        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                    "SELECT a.created_at, a.event_type, a.description, COALESCE(u.first_name || ' ' || u.last_name, u.email, a.actor_id) AS actor " +
                    "FROM audit_trail a LEFT JOIN \"user\" u ON a.actor_id = u.user_id " +
                    "ORDER BY a.created_at DESC LIMIT ?",
                    lines);
            List<String> out = new ArrayList<>();
            for (Map<String, Object> row : rows) {
                out.add(String.format("%s %s [%s] - %s", row.get("created_at"), row.get("event_type"), row.get("actor"), row.get("description")));
            }
            return out;
        } catch (Exception e) {
            return Collections.singletonList("No audit events found: " + e.getMessage());
        }
    }

    private List<String> readLastLines(File file, int lines) throws IOException {
        List<String> result = new ArrayList<>();
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            long fileLength = raf.length();
            long pos = fileLength - 1;
            int lineCount = 0;
            StringBuilder sb = new StringBuilder();

            while (pos >= 0 && lineCount < lines) {
                raf.seek(pos);
                int readByte = raf.read();
                if (readByte == '\n') {
                    if (!sb.isEmpty()) {
                        result.add(sb.reverse().toString());
                        sb.setLength(0);
                        lineCount++;
                    }
                } else if (readByte != '\r') {
                    sb.append((char) readByte);
                }
                pos--;
                if (pos < 0 && !sb.isEmpty()) {
                    result.add(sb.reverse().toString());
                    break;
                }
            }
        }
        Collections.reverse(result);
        return result;
    }
}
