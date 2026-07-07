package com.example.IT21_FinalProject;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DocumentsSigningServiceTest {

    @Test
    void verifySignatureAcceptsValidSignatureAndRejectsTamperedPayload() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        byte[] payload = "secure-document".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(payload);
        String signatureB64 = Base64.getEncoder().encodeToString(signer.sign());
        String publicKeyB64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        assertTrue(DocumentsSigningService.verifySignature(payload, signatureB64, publicKeyB64));
        assertFalse(DocumentsSigningService.verifySignature("tampered".getBytes(StandardCharsets.UTF_8), signatureB64, publicKeyB64));
    }
}
