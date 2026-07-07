package com.example.IT21_FinalProject.controller;

import com.example.IT21_FinalProject.DocumentsSigningService;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DocumentApiController {

    private final DocumentsSigningService documentsSigningService;
    private final JdbcTemplate jdbcTemplate;

    public DocumentApiController(DocumentsSigningService documentsSigningService, JdbcTemplate jdbcTemplate) {
        this.documentsSigningService = documentsSigningService;
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping(value = "/documents/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> uploadDocument(@RequestParam("file") MultipartFile file, HttpSession session) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }
        try {
            String userId = jdbcTemplate.queryForObject("SELECT user_id FROM \"user\" WHERE email = ?", String.class, userEmail);
            return ResponseEntity.ok(documentsSigningService.uploadDocument(file, userId));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
        }
    }

    @PostMapping("/documents/{id}/sign")
    public ResponseEntity<?> signDocument(@PathVariable("id") String documentId, HttpSession session) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }
        try {
            String userId = jdbcTemplate.queryForObject("SELECT user_id FROM \"user\" WHERE email = ?", String.class, userEmail);
            return ResponseEntity.ok(documentsSigningService.signDocument(documentId, userId));
        } catch (Exception ex) {
            return ResponseEntity.status(500).body(Map.of("message", ex.getMessage()));
        }
    }

    @PostMapping("/documents/{id}/verify")
    public ResponseEntity<?> verifyDocument(@PathVariable("id") String documentId, HttpSession session) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }
        try {
            String verifierId = jdbcTemplate.queryForObject("SELECT user_id FROM \"user\" WHERE email = ?", String.class, userEmail);
            return ResponseEntity.ok(documentsSigningService.verifyDocument(documentId, verifierId));
        } catch (Exception ex) {
            return ResponseEntity.status(500).body(Map.of("message", ex.getMessage()));
        }
    }

    @GetMapping("/documents/{id}/result")
    public ResponseEntity<?> documentResult(@PathVariable("id") String documentId) {
        try {
            return ResponseEntity.ok(documentsSigningService.getDocumentResult(documentId));
        } catch (Exception ex) {
            return ResponseEntity.status(500).body(Map.of("message", ex.getMessage()));
        }
    }

    @GetMapping("/documents/signed")
    public ResponseEntity<?> signedDocuments(HttpSession session) {
        String userEmail = (String) session.getAttribute("userEmail");
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("message", "Please log in first."));
        }
        try {
            String userId = jdbcTemplate.queryForObject("SELECT user_id FROM \"user\" WHERE email = ?", String.class, userEmail);
            return ResponseEntity.ok(documentsSigningService.listSignedDocuments(userId));
        } catch (Exception ex) {
            return ResponseEntity.status(500).body(Map.of("message", ex.getMessage()));
        }
    }

    @PostMapping("/auth/register")
    public ResponseEntity<?> register(@RequestParam String firstName, @RequestParam String lastName,
                                      @RequestParam String email, @RequestParam String password) {
        try {
            Map<String, Object> created = documentsSigningService.createUser(firstName, lastName, email, password, "ROL003");
            return ResponseEntity.ok(created);
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
        }
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestParam String email, @RequestParam String password, HttpSession session) {
        try {
            Map<String, Object> row = jdbcTemplate.queryForMap("SELECT user_id, password, role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)", email);
            String storedHash = (String) row.get("password");
            if (!new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().matches(password, storedHash)) {
                return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials"));
            }
            session.setAttribute("userEmail", email);
            session.setAttribute("userRole", row.get("role_id"));
            session.setAttribute("userName", email);
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("message", "Login successful");
            response.put("role", row.get("role_id"));
            return ResponseEntity.ok(response);
        } catch (Exception ex) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials"));
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public ResponseEntity<?> getUsers() {
        return ResponseEntity.ok(documentsSigningService.listUsers());
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/admin/users")
    public ResponseEntity<?> createUser(@RequestParam String firstName, @RequestParam String lastName,
                                        @RequestParam String email, @RequestParam String password,
                                        @RequestParam String roleId) {
        return ResponseEntity.ok(documentsSigningService.createUser(firstName, lastName, email, password, roleId));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/admin/users/{id}")
    public ResponseEntity<?> updateUser(@PathVariable("id") String userId, @RequestParam String firstName,
                                        @RequestParam String lastName, @RequestParam String email,
                                        @RequestParam String roleId, @RequestParam String status) {
        documentsSigningService.updateUser(userId, firstName, lastName, email, roleId, status);
        return ResponseEntity.ok(Map.of("message", "User updated"));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/keys")
    public ResponseEntity<?> listKeys() {
        return ResponseEntity.ok(documentsSigningService.listKeys());
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/admin/keys/generate")
    public ResponseEntity<?> generateKey(@RequestParam String userId) {
        return ResponseEntity.ok(documentsSigningService.generateKey(userId));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/admin/keys/{id}/revoke")
    public ResponseEntity<?> revokeKey(@PathVariable("id") String keyId) {
        documentsSigningService.revokeKey(keyId);
        return ResponseEntity.ok(Map.of("message", "Key revoked"));
    }

    @PreAuthorize("hasAnyRole('ADMIN','SECURITY_ANALYST')")
    @GetMapping("/logs/verification")
    public ResponseEntity<?> verificationLogs(@RequestParam(value = "documentId", required = false) String documentId) {
        return ResponseEntity.ok(documentsSigningService.getVerificationHistory(documentId));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/logs/audit")
    public ResponseEntity<?> auditLogs() {
        return ResponseEntity.ok(documentsSigningService.getAuditTrail());
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/dashboard/summary")
    public ResponseEntity<?> dashboardSummary() {
        return ResponseEntity.ok(documentsSigningService.getDashboardSummary());
    }
}
