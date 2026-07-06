package com.example.IT21_FinalProject;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@Service
public class SigningKeyService {

    private final JdbcTemplate jdbcTemplate;

    public SigningKeyService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Returns this user's active signing key (public + private, base64-encoded).
     * If they don't have one yet, generates and stores an RSA-2048 pair.
     *
     * NOTE: storing the raw private key in the database is fine for a school
     * project demo, but in a real system this should be encrypted at rest
     * (e.g. via a KMS or an encrypted column) rather than stored as plain base64.
     */
    public Map<String, Object> getOrCreateActiveKey(String userId) {
        try {
            return jdbcTemplate.queryForMap(
                    "SELECT key_id, public_key, private_key FROM signing_key " +
                    "WHERE user_id = ? AND status = 'Active' ORDER BY created_at DESC LIMIT 1",
                    userId);
        } catch (org.springframework.dao.EmptyResultDataAccessException e) {
            String keyId = generateKeyPairForUser(userId);
            return jdbcTemplate.queryForMap(
                    "SELECT key_id, public_key, private_key FROM signing_key WHERE key_id = ?", keyId);
        }
    }

    public String generateKeyPairForUser(String userId) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();

            String publicKeyB64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
            String privateKeyB64 = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
            String keyId = "KEY-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

            jdbcTemplate.update(
                    "INSERT INTO signing_key (key_id, user_id, key_type, public_key, private_key, status, created_at) " +
                    "VALUES (?, ?, 'RSA-2048', ?, ?, 'Active', NOW())",
                    keyId, userId, publicKeyB64, privateKeyB64);

            return keyId;
        } catch (NoSuchAlgorithmException e) {
            // RSA is a standard JCA algorithm; this should never actually happen
            throw new IllegalStateException("RSA algorithm unavailable on this JVM", e);
        }
    }
}