package com.example.IT21_FinalProject;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;

@Service
public class PasswordResetService {

    private static final int TOKEN_VALID_MINUTES = 30;

    private final JdbcTemplate jdbcTemplate;
    private final EmailService emailService;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordResetService(JdbcTemplate jdbcTemplate, EmailService emailService) {
        this.jdbcTemplate = jdbcTemplate;
        this.emailService = emailService;
    }

    /**
     * Generates a reset token, emails the reset link, and returns the link.
     * Returns null if no account exists for that email.
     */
    public String requestReset(String email, String baseUrl) {
        Map<String, Object> row;
        try {
            row = jdbcTemplate.queryForMap(
                    "SELECT user_id, email FROM \"user\" WHERE LOWER(email) = LOWER(?)",
                    email);
        } catch (EmptyResultDataAccessException ex) {
            return null;
        }

        String userId = (String) row.get("user_id");
        String accountEmail = (String) row.get("email");

        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        Timestamp expiresAt = Timestamp.valueOf(LocalDateTime.now().plusMinutes(TOKEN_VALID_MINUTES));

        jdbcTemplate.update(
                "INSERT INTO password_reset_token (token, user_id, expires_at, used) VALUES (?, ?, ?, FALSE)",
                token, userId, expiresAt);

        String resetLink = baseUrl + "/reset-password?token=" + token;
        emailService.sendPasswordResetEmail(accountEmail, resetLink);
        return resetLink;
    }

    public String validateToken(String token) {
        try {
            Map<String, Object> row = jdbcTemplate.queryForMap(
                    "SELECT user_id, expires_at, used FROM password_reset_token WHERE token = ?",
                    token);

            boolean used = (Boolean) row.get("used");
            Timestamp expiresAt = (Timestamp) row.get("expires_at");

            if (used || expiresAt.toLocalDateTime().isBefore(LocalDateTime.now())) {
                return null;
            }
            return (String) row.get("user_id");
        } catch (EmptyResultDataAccessException ex) {
            return null;
        }
    }

    public boolean resetPassword(String token, String newPassword) {
        String userId = validateToken(token);
        if (userId == null) {
            return false;
        }

        String encoded = passwordEncoder.encode(newPassword);
        jdbcTemplate.update("UPDATE \"user\" SET password = ? WHERE user_id = ?", encoded, userId);
        jdbcTemplate.update("UPDATE password_reset_token SET used = TRUE WHERE token = ?", token);

        return true;
    }
}