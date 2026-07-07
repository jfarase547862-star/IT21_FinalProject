package com.example.IT21_FinalProject;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Controller
public class HomeController {

	private final JdbcTemplate jdbcTemplate;
	private final DocumentsSigningService documentsSigningService;

	private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	@Autowired
	public HomeController(JdbcTemplate jdbcTemplate, DocumentsSigningService documentsSigningService) {
		this.jdbcTemplate = jdbcTemplate;
		this.documentsSigningService = documentsSigningService;
	}

	@GetMapping({"/", "/login"})
	public String login(
			@RequestParam(value = "message", required = false) String message,
			@RequestParam(value = "error", required = false) String error,
			Model model) {
		if (message != null && !message.isBlank()) {
			model.addAttribute("statusMessage", message);
		}
		if (error != null && !error.isBlank()) {
			model.addAttribute("errorMessage", error);
		}
		return "login";
	}

	@PostMapping("/login")
	public String loginSubmit(
			@RequestParam String email,
			@RequestParam String password,
			HttpSession session,
			Model model) {
		try {
			Map<String, Object> row = jdbcTemplate.queryForMap(
					"SELECT first_name || ' ' || last_name AS name, role_id, password FROM \"user\" WHERE LOWER(email) = LOWER(?)",
					email);

			String storedHash = (String) row.get("password");
			String userName = (String) row.get("name");
			String roleId = (String) row.get("role_id");

			boolean authenticated = false;
			if (storedHash != null && (storedHash.startsWith("$2a$") || storedHash.startsWith("$2b$") || storedHash.startsWith("$2y$"))) {
				authenticated = passwordEncoder.matches(password, storedHash);
			} else {
				// legacy plaintext seed: compare directly then migrate to bcrypt
				authenticated = password.equals(storedHash);
				if (authenticated) {
					String newHash = passwordEncoder.encode(password);
					jdbcTemplate.update("UPDATE \"user\" SET password = ? WHERE LOWER(email) = LOWER(?)", newHash, email);
				}
			}

			if (authenticated) {
				session.setAttribute("userName", userName);
				session.setAttribute("userRole", roleId);
				session.setAttribute("userEmail", email);

				// Redirect directly to role-specific dashboard
				if ("ROL001".equals(roleId)) {
					return "redirect:/dashboard/admin";
				} else if ("ROL004".equals(roleId)) {
					return "redirect:/dashboard/analyst";
				} else {
					return "redirect:/dashboard/signer";
				}
			}
		} catch (EmptyResultDataAccessException ignored) {
		}

		model.addAttribute("errorMessage", "Invalid email or password.");
		return "login";
	}

	@GetMapping("/signup")
	public String signup() {
		return "signup";
	}

	@PostMapping("/signup")
	public String signupSubmit(
			@RequestParam String firstName,
			@RequestParam String lastName,
			@RequestParam String email,
			@RequestParam String password,
			@RequestParam String confirmPassword,
			Model model) {

		if (!password.equals(confirmPassword)) {
			model.addAttribute("errorMessage", "Passwords do not match.");
			return "signup";
		}

		String pwdError = validatePassword(password);
		if (pwdError != null) {
			model.addAttribute("errorMessage", pwdError);
			return "signup";
		}

		String defaultRoleId = "ROL003";
		jdbcTemplate.update(
			"INSERT INTO role (role_id, role_name, description) VALUES (?, ?, ?) ON CONFLICT (role_id) DO NOTHING",
			defaultRoleId,
			"Staff",
			"Staff user role");

String userId = generateUserId();
		String encoded = passwordEncoder.encode(password);

		int inserted = jdbcTemplate.update(
			"INSERT INTO \"user\" (user_id, first_name, last_name, email, password, role_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW()) ON CONFLICT (email) DO NOTHING",
			userId,
			firstName,
			lastName,
			email,
			encoded,
			defaultRoleId,
			"Active");

		if (inserted == 0) {
			model.addAttribute("errorMessage", "Email already exists.");
			return "signup";
		}

		return "redirect:/login?message=Signup+successful.+Please+log+in.";
	}

	@GetMapping({"/dashboard", "/dashboard/"})
	public String dashboard(HttpSession session) {
		String userEmail = (String) session.getAttribute("userEmail");
		if (userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}

		try {
			String roleId = jdbcTemplate.queryForObject(
					"SELECT role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
					String.class,
					userEmail);
			if ("ROL001".equals(roleId)) {
				return "redirect:/dashboard/admin";
			}
			if ("ROL004".equals(roleId)) {
				return "redirect:/dashboard/analyst";
			}
			return "redirect:/dashboard/signer";
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}
	}

	@GetMapping({"/dashboard/admin", "/dashboard/admin/", "/admin"})
	public String adminDashboard(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");
		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}
		// verify role from DB
		String roleId;
		try {
			roleId = jdbcTemplate.queryForObject("SELECT role_id FROM \"user\" WHERE email = ?", String.class, userEmail);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL001".equals(roleId)) {
			return "redirect:/dashboard";
		}

		Map<String, Object> stats = new LinkedHashMap<>();
		try {
			Integer totalUsers = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM \"user\"", Integer.class);
			Integer totalDocuments = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM document", Integer.class);
			Integer signedDocuments = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM digital_signature", Integer.class);
			Integer pendingDocuments = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM document WHERE document_status <> 'Signed'", Integer.class);
			stats.put("totalUsers", totalUsers != null ? totalUsers : 0);
			stats.put("totalDocuments", totalDocuments != null ? totalDocuments : 0);
			stats.put("signedDocuments", signedDocuments != null ? signedDocuments : 0);
			stats.put("pendingDocuments", pendingDocuments != null ? pendingDocuments : 0);
		} catch (Exception ignored) {
			stats.put("totalUsers", 0);
			stats.put("totalDocuments", 0);
			stats.put("signedDocuments", 0);
			stats.put("pendingDocuments", 0);
		}

		List<Map<String, Object>> recentActivity = jdbcTemplate.queryForList(
				"SELECT vl.checked_at AS created_at, " +
						"CASE " +
						" WHEN vl.outcome = 'AUTHENTIC' THEN 'VERIFICATION_VALID' " +
						" WHEN vl.outcome = 'TAMPERED' THEN 'VERIFICATION_TAMPERED' " +
						" ELSE 'VERIFICATION_FAILED' " +
						"END AS event_type, " +
						"'Document ' || d.document_id || ' (' || d.file_name || ') verified as ' || vl.outcome AS description " +
						"FROM verification_log vl " +
						"JOIN document d ON d.document_id = vl.document_id " +
						"ORDER BY vl.checked_at DESC LIMIT 8");
		for (Map<String, Object> entry : recentActivity) {
			entry.put("eventClass", resolveAuditEventClass(String.valueOf(entry.get("event_type"))));
		}

		model.addAttribute("userName", userName);
		model.addAttribute("stats", stats);
		model.addAttribute("recentActivity", recentActivity);
		return "admin/admin-dashboard";
	}

	@GetMapping({"/admin/users", "/admin/users/"})
	public String adminUsers(
			@RequestParam(value = "message", required = false) String message,
			@RequestParam(value = "error", required = false) String error,
			HttpSession session,
			Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");
		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}
		String roleId;
		try {
			roleId = jdbcTemplate.queryForObject("SELECT role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)", String.class, userEmail);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL001".equals(roleId)) {
			return "redirect:/dashboard";
		}

		List<Map<String, Object>> users = jdbcTemplate.queryForList(
				"SELECT u.user_id, u.first_name, u.last_name, u.email, u.role_id, r.role_name, u.status, u.created_at FROM \"user\" u JOIN role r ON u.role_id = r.role_id ORDER BY u.created_at DESC");
		List<Map<String, Object>> roles = jdbcTemplate.queryForList(
				"SELECT role_id, role_name FROM role ORDER BY role_name");

		model.addAttribute("userName", userName);
		model.addAttribute("users", users);
		model.addAttribute("roles", roles);
		if (message != null && !message.isBlank()) {
			model.addAttribute("statusMessage", message);
		}
		if (error != null && !error.isBlank()) {
			model.addAttribute("errorMessage", error);
		}

		return "admin/users";
	}

	@PostMapping("/admin/users/create")
	public String createAdminUser(
			@RequestParam String firstName,
			@RequestParam String lastName,
			@RequestParam String email,
			@RequestParam String password,
			@RequestParam String confirmPassword,
			@RequestParam String roleId,
			HttpSession session,
			Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");
		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}
		String currentRoleId;
		try {
			currentRoleId = jdbcTemplate.queryForObject("SELECT role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)", String.class, userEmail);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL001".equals(currentRoleId)) {
			return "redirect:/dashboard";
		}

		if (firstName == null || firstName.isBlank() || lastName == null || lastName.isBlank()
			|| email == null || email.isBlank() || password == null || password.isBlank()
			|| confirmPassword == null || confirmPassword.isBlank()) {
			return "redirect:/admin/users?error=All+fields+are+required.";
		}

		if (!password.equals(confirmPassword)) {
			return "redirect:/admin/users?error=Passwords+do+not+match.";
		}

		String pwdError = validatePassword(password);
		if (pwdError != null) {
			return "redirect:/admin/users?error=" + pwdError.replace(" ", "+");
		}

		Integer existing = jdbcTemplate.queryForObject(
				"SELECT COUNT(*) FROM \"user\" WHERE LOWER(email) = LOWER(?)", Integer.class, email);
		if (existing != null && existing > 0) {
			return "redirect:/admin/users?error=Email+already+exists.";
		}

String newUserId = generateUserId();
		String encoded = passwordEncoder.encode(password);
		jdbcTemplate.update(
				"INSERT INTO \"user\" (user_id, first_name, last_name, email, password, role_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'Active', NOW())",
				newUserId,
				firstName,
				lastName,
				email,
				encoded,
				roleId);

		return "redirect:/admin/users?message=User+created+successfully.";
	}

	@PostMapping("/admin/users/update-name")
	public String updateAdminUserName(
			@RequestParam String userId,
			@RequestParam String firstName,
			@RequestParam String lastName,
			HttpSession session,
			Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");
		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}
		String currentRoleId;
		try {
			currentRoleId = jdbcTemplate.queryForObject("SELECT role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)", String.class, userEmail);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL001".equals(currentRoleId)) {
			return "redirect:/dashboard";
		}

		if (firstName == null || firstName.isBlank() || lastName == null || lastName.isBlank()) {
			return "redirect:/admin/users?error=All+fields+are+required.";
		}

		jdbcTemplate.update(
				"UPDATE \"user\" SET first_name = ?, last_name = ? WHERE user_id = ?",
				firstName,
				lastName,
				userId);

		return "redirect:/admin/users?message=User+updated+successfully.";
	}

	@GetMapping({"/admin/keys", "/admin/keys/"})
	public String adminKeys(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");
		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}
		String roleId;
		try {
			roleId = jdbcTemplate.queryForObject("SELECT role_id FROM \"user\" WHERE email = ?", String.class, userEmail);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL001".equals(roleId)) {
			return "redirect:/dashboard";
		}
		model.addAttribute("userName", userName);
		return "admin/keys";
	}

	@GetMapping({"/admin/logs", "/admin/logs/"})
	public String adminLogs(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");
		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}
		String roleId;
		try {
			roleId = jdbcTemplate.queryForObject("SELECT role_id FROM \"user\" WHERE email = ?", String.class, userEmail);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL001".equals(roleId)) {
			return "redirect:/dashboard";
		}

		List<Map<String, Object>> auditEvents = jdbcTemplate.queryForList(
				"SELECT created_at, event_type, description, actor_id FROM audit_trail ORDER BY created_at DESC LIMIT 25");
		List<Map<String, Object>> normalizedEvents = new java.util.ArrayList<>();
		for (Map<String, Object> event : auditEvents) {
			Map<String, Object> normalized = new LinkedHashMap<>();
			String eventType = String.valueOf(event.getOrDefault("event_type", "AUDIT_EVENT"));
			normalized.put("title", eventType);
			normalized.put("description", String.valueOf(event.getOrDefault("description", "No details available.")));
			normalized.put("timeAgo", String.valueOf(event.getOrDefault("created_at", "Now")));
			normalized.put("actorId", String.valueOf(event.getOrDefault("actor_id", "—")));
			normalized.put("eventClass", resolveAuditEventClass(eventType));
			normalizedEvents.add(normalized);
		}

		model.addAttribute("userName", userName);
		model.addAttribute("auditEvents", normalizedEvents);
		return "admin/logs";
	}

	@GetMapping({"/admin/reports", "/admin/reports/"})
	public String adminReports(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");
		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}
		String roleId;
		try {
			roleId = jdbcTemplate.queryForObject("SELECT role_id FROM \"user\" WHERE email = ?", String.class, userEmail);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL001".equals(roleId)) {
			return "redirect:/dashboard";
		}
		model.addAttribute("userName", userName);
		return "admin/reports";
	}

	@GetMapping({"/admin/monitor", "/admin/monitor/"})
	public String adminMonitor(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");
		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}
		String roleId;
		try {
			roleId = jdbcTemplate.queryForObject("SELECT role_id FROM \"user\" WHERE email = ?", String.class, userEmail);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL001".equals(roleId)) {
			return "redirect:/dashboard";
		}
		model.addAttribute("userName", userName);
		return "admin/monitor";
	}

	@GetMapping("/logout")
	public String logout(HttpSession session) {
		if (session != null) {
			session.invalidate();
		}
		return "redirect:/login?message=Logged+out+successfully.";
	}

	@GetMapping({"/dashboard/analyst", "/dashboard/analyst/", "/analyst"})
	public String analystDashboard(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");
		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}
		String roleId;
		try {
			roleId = jdbcTemplate.queryForObject("SELECT role_id FROM \"user\" WHERE email = ?", String.class, userEmail);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL004".equals(roleId)) {
			return "redirect:/dashboard";
		}

		Map<String, Object> stats = new LinkedHashMap<>();
		try {
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
			stats.put("verifiedDocuments", verifiedDocuments != null ? verifiedDocuments : 0);
			stats.put("pendingDocuments", pendingDocuments != null ? pendingDocuments : 0);
			stats.put("recentAlerts", recentAlerts != null ? recentAlerts : 0);
		} catch (Exception ignored) {
			stats.put("verifiedDocuments", 0);
			stats.put("pendingDocuments", 0);
			stats.put("recentAlerts", 0);
		}

		List<Map<String, Object>> recentActivity = jdbcTemplate.queryForList(
				"SELECT created_at, event_type, description FROM audit_trail ORDER BY created_at DESC LIMIT 5");

		model.addAttribute("userName", userName);
		model.addAttribute("stats", stats);
		model.addAttribute("recentActivity", recentActivity);
		return "analyst/analyst-dashboard";
	}
	
	

@GetMapping({"/dashboard/signer", "/dashboard/signer/", "/signer"})
public String staffDashboard(HttpSession session, Model model) {
    String userName = (String) session.getAttribute("userName");
    String userEmail = (String) session.getAttribute("userEmail");
    if (userName == null || userEmail == null) {
        return "redirect:/login?error=Please+log+in+first.";
    }
    model.addAttribute("userName", userName);

    String userId = resolveUserId(userEmail);

    // Real-time stat counts for this user's documents
    try {
        Integer verifiedCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(DISTINCT vl.document_id) FROM verification_log vl " +
                "JOIN document d ON vl.document_id = d.document_id WHERE d.user_id = ?",
                Integer.class, userId);
        Integer pendingCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM document d WHERE d.user_id = ? AND d.document_status = 'Signed' " +
                "AND NOT EXISTS (SELECT 1 FROM verification_log vl WHERE vl.document_id = d.document_id)",
                Integer.class, userId);
        Integer failedCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM verification_log vl JOIN document d ON vl.document_id = d.document_id " +
                "WHERE d.user_id = ? AND vl.outcome IN ('FAILED', 'TAMPERED')",
                Integer.class, userId);

        model.addAttribute("verifiedCount", verifiedCount != null ? verifiedCount : 0);
        model.addAttribute("pendingCount", pendingCount != null ? pendingCount : 0);
        model.addAttribute("failedCount", failedCount != null ? failedCount : 0);
    } catch (Exception ignored) {
        model.addAttribute("verifiedCount", 0);
        model.addAttribute("pendingCount", 0);
        model.addAttribute("failedCount", 0);
    }

    // Load analyst-verified history only
    try {
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "SELECT vl.document_id, d.file_name, vl.outcome, vl.checked_at " +
                "FROM verification_log vl JOIN document d ON vl.document_id = d.document_id " +
                "WHERE d.user_id = ? ORDER BY vl.checked_at DESC LIMIT 20",
                userId);
        List<Map<String, Object>> history = new java.util.ArrayList<>();
        for (Map<String, Object> r : rows) {
            Map<String, Object> item = new java.util.LinkedHashMap<>();
            item.put("id", r.get("document_id"));
            item.put("documentName", r.get("file_name"));
            Object v = r.get("checked_at");
            item.put("verifiedAt", formatTimestamp(v));
            String outcome = String.valueOf(r.get("outcome"));
            item.put("status", "AUTHENTIC".equals(outcome) ? "Verified" : ("TAMPERED".equals(outcome) ? "Tampered" : "Failed"));
            history.add(item);
        }
        model.addAttribute("history", history);
    } catch (Exception ignored) {
        // silently ignore history loading errors to avoid breaking the dashboard
    }

    return "signer/dashboard";
}

	@GetMapping({"/signer/upload", "/signer/upload/"})
	public String staffUpload(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");
		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}
		model.addAttribute("userName", userName);
		return "signer/upload";
	}

	@GetMapping({"/analyst/verify", "/analyst/verify/"})
	public String analystVerify(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");

		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}

		String roleId;
		try {
			roleId = jdbcTemplate.queryForObject(
					"SELECT role_id FROM \"user\" WHERE email = ?",
					String.class,
					userEmail
			);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL004".equals(roleId)) {
			return "redirect:/dashboard";
		}

		model.addAttribute("userName", userName);
		try {
			List<Map<String, Object>> rows = jdbcTemplate.queryForList(
					"SELECT d.document_id, d.file_name, d.upload_date, " +
							"COALESCE(u.first_name || ' ' || u.last_name, d.user_id) AS signer_name " +
							"FROM document d " +
							"LEFT JOIN \"user\" u ON d.user_id = u.user_id " +
							"WHERE UPPER(d.document_status) = 'SIGNED' " +
							"AND NOT EXISTS (SELECT 1 FROM verification_log vl WHERE vl.document_id = d.document_id) " +
							"ORDER BY d.upload_date DESC LIMIT 50");

			List<Map<String, Object>> pendingQueue = new java.util.ArrayList<>();
			for (Map<String, Object> row : rows) {
				Map<String, Object> item = new LinkedHashMap<>();
				item.put("documentId", row.get("document_id"));
				item.put("docName", row.get("file_name"));
				item.put("signedAt", formatTimestamp(row.get("upload_date")));
				item.put("signer", row.get("signer_name"));
				item.put("status", "Awaiting Review");
				pendingQueue.add(item);
			}
			model.addAttribute("pendingQueue", pendingQueue);
		} catch (Exception ignored) {
			model.addAttribute("pendingQueue", List.of());
		}
		return "analyst/verify";
	}

	@PostMapping(value = {"/verify", "/analyst/verify"}, consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody
	public Map<String, Object> handleAnalystVerification(
			@RequestParam(value = "document", required = false) MultipartFile document,
			@RequestParam(value = "file", required = false) MultipartFile file,
			HttpSession session) {
		MultipartFile uploadedFile = document != null ? document : file;
		Map<String, Object> result = new LinkedHashMap<>();
		if (uploadedFile == null || uploadedFile.isEmpty()) {
			result.put("status", "ERROR");
			result.put("message", "No file uploaded");
			return result;
		}

		String userEmail = (String) session.getAttribute("userEmail");
		if (userEmail == null) {
			result.put("status", "ERROR");
			result.put("message", "Please log in first.");
			return result;
		}

		try {
			byte[] bytes = uploadedFile.getBytes();
			java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(bytes);
			StringBuilder sb = new StringBuilder();
			for (byte b : digest) sb.append(String.format("%02x", b));
			String hash = sb.toString();

			try {
				Map<String, Object> row = jdbcTemplate.queryForMap(
						"SELECT s.signature_id, s.document_id, s.signature_hash, s.signature_value, s.public_key, s.signed_at, s.key_id, s.signer_id, d.file_name " +
							"FROM digital_signature s JOIN document d ON s.document_id = d.document_id WHERE s.signature_hash = ? ORDER BY s.signed_at DESC LIMIT 1",
						hash);

				boolean signatureValid = DocumentsSigningService.verifySignature(bytes, (String) row.get("signature_value"), (String) row.get("public_key"));
				boolean integrityMatch = hash.equals(String.valueOf(row.get("signature_hash")));
				boolean certificateValid = signatureValid && integrityMatch;

				String documentId = (String) row.get("document_id");
				String analystId = jdbcTemplate.queryForObject(
						"SELECT user_id FROM \"user\" WHERE email = ?", String.class, userEmail);
				Map<String, Object> verification = documentsSigningService.verifyDocument(documentId, analystId);
				String outcome = String.valueOf(verification.get("outcome"));

				String status;
				if ("AUTHENTIC".equals(outcome)) {
					status = "VALID";
				} else if ("TAMPERED".equals(outcome)) {
					status = "TAMPERED";
				} else {
					status = "INVALID";
				}

				result.put("status", status);
				result.put("rsaSignatureValid", signatureValid);
				result.put("integrityMatch", integrityMatch);
				result.put("certificateValid", certificateValid);
				result.put("signer", row.get("signer_id"));
				result.put("timestamp", String.valueOf(verification.get("timestamp")));
				result.put("hash", hash);
				result.put("fileName", row.get("file_name"));
				result.put("signatureId", row.get("signature_id"));
				result.put("keyId", row.get("key_id"));
				result.put("documentId", documentId);
				result.put("outcome", outcome);
				return result;
			} catch (org.springframework.dao.EmptyResultDataAccessException ex) {
				result.put("status", "INVALID");
				result.put("rsaSignatureValid", false);
				result.put("integrityMatch", false);
				result.put("certificateValid", false);
				result.put("hash", hash);
				return result;
			}
		} catch (Exception e) {
			result.put("status", "ERROR");
			result.put("message", e.getMessage());
			return result;
		}
	}

	@GetMapping({"/analyst/history", "/analyst/history/"})
	public String analystHistory(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");

		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}

		String roleId;
		try {
			roleId = jdbcTemplate.queryForObject(
					"SELECT role_id FROM \"user\" WHERE email = ?",
					String.class,
					userEmail
			);
		} catch (EmptyResultDataAccessException e) {
			return "redirect:/login?error=User+not+found.";
		}

		if (!"ROL004".equals(roleId)) {
			return "redirect:/dashboard";
		}

		model.addAttribute("userName", userName);

		try {
			List<Map<String, Object>> rows = jdbcTemplate.queryForList(
					"SELECT vl.verification_id, vl.document_id, vl.outcome, vl.checked_at, ds.signature_id, ds.signature_hash, " +
							"COALESCE(signer_u.first_name || ' ' || signer_u.last_name, ds.signer_id) AS signer, " +
							"COALESCE(analyst_u.first_name || ' ' || analyst_u.last_name, vl.verifier_id) AS verified_by, " +
							"d.file_name " +
							"FROM verification_log vl " +
							"JOIN document d ON d.document_id = vl.document_id " +
							"JOIN digital_signature ds ON ds.document_id = vl.document_id " +
							"LEFT JOIN \"user\" signer_u ON signer_u.user_id = ds.signer_id " +
							"LEFT JOIN \"user\" analyst_u ON analyst_u.user_id = vl.verifier_id " +
							"ORDER BY vl.checked_at DESC LIMIT 50");
			List<Map<String, Object>> history = new java.util.ArrayList<>();
			for (Map<String, Object> r : rows) {
				Map<String, Object> item = new java.util.LinkedHashMap<>();
				item.put("id", r.get("signature_id"));
				item.put("documentId", r.get("document_id"));
				item.put("docName", r.get("file_name"));
				item.put("verifiedAt", formatTimestamp(r.get("checked_at")));
				item.put("signer", r.get("signer"));
				item.put("verifiedBy", r.get("verified_by"));
				item.put("hash", r.get("signature_hash"));
				String outcome = String.valueOf(r.get("outcome"));
				item.put("status", "AUTHENTIC".equals(outcome) ? "VALID" : ("TAMPERED".equals(outcome) ? "TAMPERED" : "INVALID"));
				history.add(item);
			}
			model.addAttribute("history", history);
		} catch (Exception ignored) {
		}

		return "analyst/history";
	}

	@GetMapping({"/signer/results", "/signer/results/"})
	public String staffResults(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");

		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}

		model.addAttribute("userName", userName);

		try {
			String userId = resolveUserId(userEmail);
			List<Map<String, Object>> rows = jdbcTemplate.queryForList(
					"SELECT vl.document_id, d.file_name, vl.outcome, vl.checked_at, " +
							"COALESCE(u.first_name || ' ' || u.last_name, vl.verifier_id) AS verifier " +
							"FROM verification_log vl " +
							"JOIN document d ON vl.document_id = d.document_id " +
							"LEFT JOIN \"user\" u ON vl.verifier_id = u.user_id " +
							"WHERE d.user_id = ? ORDER BY vl.checked_at DESC LIMIT 10",
					userId);
			List<Map<String, Object>> history = new java.util.ArrayList<>();
			for (Map<String, Object> r : rows) {
				Map<String, Object> item = new java.util.LinkedHashMap<>();
				item.put("id", r.get("document_id"));
				item.put("documentName", r.get("file_name"));
				item.put("verifiedAt", formatTimestamp(r.get("checked_at")));
				item.put("signer", r.get("verifier"));
				String outcome = String.valueOf(r.get("outcome"));
				item.put("status", "AUTHENTIC".equals(outcome) ? "Verified" : ("TAMPERED".equals(outcome) ? "Tampered" : "Failed"));
				history.add(item);
			}
			model.addAttribute("history", history);
		} catch (Exception ignored) {
		}

		return "signer/results";
	}

	@GetMapping({"/signer/download", "/signer/download/"})
	public String staffDownload(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");

		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}

		String userId = resolveUserId(userEmail);
		List<Map<String, Object>> documents = loadSignedDocuments(userId);

		model.addAttribute("userName", userName);
		model.addAttribute("documents", documents);
		return "signer/download";
	}

	@GetMapping("/signer/download/{documentId}")
	public ResponseEntity<Resource> downloadSignedDocument(@PathVariable String documentId, HttpSession session) throws IOException {
		String userEmail = (String) session.getAttribute("userEmail");
		if (userEmail == null) {
			return ResponseEntity.status(401).build();
		}

		String userId = resolveUserId(userEmail);
		Map<String, Object> row;
		try {
			row = jdbcTemplate.queryForMap(
					"SELECT file_name, file_path FROM document WHERE document_id = ? AND user_id = ? AND document_status = 'Signed'",
					documentId,
					userId);
		} catch (EmptyResultDataAccessException ex) {
			return ResponseEntity.notFound().build();
		}

		Path filePath = Paths.get((String) row.get("file_path"));
		if (!Files.exists(filePath)) {
			return ResponseEntity.notFound().build();
		}

		Resource resource = new UrlResource(filePath.toUri());
		String fileName = String.valueOf(row.get("file_name"));
		return ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
				.contentType(MediaType.APPLICATION_OCTET_STREAM)
				.body(resource);
	}

	@GetMapping({"/signer/apply", "/signer/apply/"})
	public String staffApply(HttpSession session, Model model) {
		String userName = (String) session.getAttribute("userName");
		String userEmail = (String) session.getAttribute("userEmail");

		if (userName == null || userEmail == null) {
			return "redirect:/login?error=Please+log+in+first.";
		}

		model.addAttribute("userName", userName);
		return "signer/apply";
	}

	private String resolveUserId(String email) {
		try {
			return jdbcTemplate.queryForObject(
					"SELECT user_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
					String.class,
					email);
		} catch (EmptyResultDataAccessException ex) {
			return null;
		}
	}

	private List<Map<String, Object>> loadSignedDocuments(String userId) {
		if (userId == null) {
			return List.of();
		}

		List<Map<String, Object>> rows = jdbcTemplate.queryForList(
				"SELECT d.document_id, d.file_name, d.upload_date, d.file_size, d.file_path, " +
				"CASE WHEN EXISTS (SELECT 1 FROM verification_log vl WHERE vl.document_id = d.document_id) " +
				"THEN 'Verified' ELSE 'Awaiting Review' END AS review_status " +
				"FROM document d WHERE d.user_id = ? AND d.document_status = 'Signed' ORDER BY d.upload_date DESC",
				userId);

		List<Map<String, Object>> documents = new java.util.ArrayList<>();
		for (Map<String, Object> row : rows) {
			Map<String, Object> document = new LinkedHashMap<>();
			document.put("id", row.get("document_id"));
			document.put("name", row.get("file_name"));
			document.put("date", formatTimestamp(row.get("upload_date")));
			document.put("size", formatFileSize(row.get("file_size")));
			document.put("downloadUrl", "/signer/download/" + row.get("document_id"));
			document.put("reviewStatus", row.get("review_status"));
			documents.add(document);
		}
		return documents;
	}

	private String formatTimestamp(Object value) {
		if (value instanceof Timestamp timestamp) {
			return DateTimeFormatter.ofPattern("yyyy-MM-dd").format(timestamp.toLocalDateTime());
		}
		return String.valueOf(value);
	}

	private String formatFileSize(Object value) {
		if (value instanceof Number number) {
			long bytes = number.longValue();
			if (bytes < 1024) return bytes + " B";
			int exp = (int) (Math.log(bytes) / Math.log(1024));
			char pre = "KMGTPE".charAt(exp - 1);
			return String.format("%.1f %sB", bytes / Math.pow(1024, exp), pre);
		}
		return "0 B";
	}

	private String validatePassword(String password) {
		if (password == null) return "Password is required.";
		if (password.length() < 8) return "Password must be at least 8 characters long.";
		if (!password.matches(".*[A-Z].*")) return "Password must contain at least one uppercase letter.";
		if (!password.matches(".*[a-z].*")) return "Password must contain at least one lowercase letter.";
		if (!password.matches(".*\\d.*")) return "Password must contain at least one digit.";
		if (!password.matches(".*[!@#$%^&*()_+\\-\\=\\[\\]{};':\\\"\\\\|,.<>/?].*")) return "Password must contain at least one special character.";
		if (password.matches(".*\\s.*")) return "Password must not contain whitespace.";
		return null;
	}

	private String generateUserId() {
		Integer nextNumber = jdbcTemplate.queryForObject(
				"SELECT COALESCE(MAX(CAST(SUBSTRING(user_id, 4) AS INTEGER)), 0) + 1 FROM \"user\" WHERE user_id LIKE 'USR%';",
				Integer.class);
		return String.format("USR%03d", nextNumber);
	}

	private String resolveAuditEventClass(String eventType) {
		String normalized = eventType == null ? "" : eventType.toUpperCase();
		if (normalized.contains("TAMPERED")) {
			return "warning";
		}
		if (normalized.contains("FAILED") || normalized.contains("ERROR") || normalized.contains("DENIED")) {
			return "error";
		}
		if (normalized.contains("AUTHENTIC") || normalized.contains("SIGNED") || normalized.contains("SUCCESS") || normalized.contains("VALID")) {
			return "success";
		}
		return "info";
	}
}