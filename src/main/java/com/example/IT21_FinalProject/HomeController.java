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

	private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	@Autowired
	public HomeController(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
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
				"SELECT created_at, event_type, description FROM audit_trail ORDER BY created_at DESC LIMIT 5");

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
				"SELECT created_at, event_type, description FROM audit_trail ORDER BY created_at DESC LIMIT 10");
		List<Map<String, Object>> normalizedEvents = new java.util.ArrayList<>();
		for (Map<String, Object> event : auditEvents) {
			Map<String, Object> normalized = new LinkedHashMap<>();
			normalized.put("title", String.valueOf(event.getOrDefault("event_type", "AUDIT_EVENT")));
			normalized.put("description", String.valueOf(event.getOrDefault("description", "No details available.")));
			normalized.put("timeAgo", String.valueOf(event.getOrDefault("created_at", "Now")));
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
			Integer verifiedDocuments = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM digital_signature", Integer.class);
			Integer pendingDocuments = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM document WHERE document_status <> 'Signed'", Integer.class);
			Integer recentAlerts = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM audit_trail WHERE event_type IN ('VERIFICATION_FAILED', 'SIGNATURE_REVOKED')", Integer.class);
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

    return "analyst/verify";
}

@PostMapping(value = {"/verify", "/analyst/verify"}, consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	@org.springframework.web.bind.annotation.ResponseBody
	public Map<String, Object> handleAnalystVerification(
			@RequestParam(value = "document", required = false) MultipartFile document,
			@RequestParam(value = "file", required = false) MultipartFile file) {
		MultipartFile uploadedFile = document != null ? document : file;
		Map<String, Object> result = new LinkedHashMap<>();
		if (uploadedFile == null || uploadedFile.isEmpty()) {
			result.put("status", "ERROR");
			result.put("message", "No file uploaded");
			return result;
		}

		try {
			byte[] bytes = uploadedFile.getBytes();
			java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(bytes);
			StringBuilder sb = new StringBuilder();
			for (byte b : digest) sb.append(String.format("%02x", b));
			String hash = sb.toString();

			// look up signature by hash
			try {
				Map<String, Object> row = jdbcTemplate.queryForMap(
						"SELECT s.signature_id, s.signature_hash, s.signed_at, s.key_id, s.signer_id, d.file_name FROM digital_signature s JOIN document d ON s.document_id = d.document_id WHERE s.signature_hash = ? ORDER BY s.signed_at DESC LIMIT 1",
						hash);

				result.put("status", "VALID");
				result.put("rsaSignatureValid", true);
				result.put("integrityMatch", true);
				result.put("certificateValid", true);
				result.put("signer", row.get("signer_id"));
				result.put("timestamp", String.valueOf(row.get("signed_at")));
				result.put("hash", hash);
				result.put("fileName", row.get("file_name"));
				result.put("signatureId", row.get("signature_id"));
				return result;
			} catch (org.springframework.dao.EmptyResultDataAccessException ex) {
				// no matching signature
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

    // Only Security Analysts can access this page
    if (!"ROL004".equals(roleId)) {
        return "redirect:/dashboard";
    }

    model.addAttribute("userName", userName);

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
				"SELECT document_id, file_name, upload_date, file_size, file_path FROM document WHERE user_id = ? AND document_status = 'Signed' ORDER BY upload_date DESC",
				userId);

		List<Map<String, Object>> documents = new LinkedHashMap<String, Object>() == null ? List.of() : new java.util.ArrayList<>();
		for (Map<String, Object> row : rows) {
			Map<String, Object> document = new LinkedHashMap<>();
			document.put("id", row.get("document_id"));
			document.put("name", row.get("file_name"));
			document.put("date", formatTimestamp(row.get("upload_date")));
			document.put("size", formatFileSize(row.get("file_size")));
			document.put("downloadUrl", "/signer/download/" + row.get("document_id"));
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
}