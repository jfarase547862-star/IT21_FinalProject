package com.example.IT21_FinalProject;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;
    private final String fromAddress;
    private final boolean mailEnabled;

    public EmailService(
            JavaMailSender mailSender,
            @Value("${spring.mail.username:}") String mailUsername,
            @Value("${app.mail.from:}") String configuredFrom) {
        this.mailSender = mailSender;
        this.fromAddress = (configuredFrom != null && !configuredFrom.isBlank())
                ? configuredFrom.trim()
                : mailUsername;
        this.mailEnabled = fromAddress != null
                && !fromAddress.isBlank()
                && !fromAddress.contains("your-email@gmail.com");
    }

    public void sendPasswordResetEmail(String toEmail, String resetLink) {
        if (!mailEnabled) {
            System.out.println("[SignaSure] Mail not configured. Password reset link for "
                    + toEmail + ": " + resetLink);
            return;
        }

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(toEmail);
        message.setSubject("SignaSure Password Reset");
        message.setText("""
                Hello,

                We received a request to reset your SignaSure password.

                Open this link within 30 minutes:
                %s

                If you did not request this, you can ignore this email.

                SignaSure
                """.formatted(resetLink));
        mailSender.send(message);
    }
}
