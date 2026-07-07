package com.example.IT21_FinalProject;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ForgotPasswordController {

    private final PasswordResetService passwordResetService;
    private final String configuredBaseUrl;

    public ForgotPasswordController(
            PasswordResetService passwordResetService,
            @Value("${app.base-url:}") String configuredBaseUrl) {
        this.passwordResetService = passwordResetService;
        this.configuredBaseUrl = configuredBaseUrl;
    }

    @GetMapping("/forgot-password")
    public String showForgotPasswordForm() {
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String handleForgotPassword(@RequestParam String email,
                                        HttpServletRequest request,
                                        Model model) {
        passwordResetService.requestReset(email, resolveBaseUrl(request));

        model.addAttribute("statusMessage",
                "If an account exists for that email, a reset link has been sent.");
        return "forgot-password";
    }

    @GetMapping("/reset-password")
    public String showResetPasswordForm(@RequestParam String token, Model model) {
        if (passwordResetService.validateToken(token) == null) {
            model.addAttribute("errorMessage", "This reset link is invalid or has expired.");
            return "forgot-password";
        }
        model.addAttribute("token", token);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String handleResetPassword(@RequestParam String token,
                                       @RequestParam String password,
                                       @RequestParam String confirmPassword,
                                       Model model) {
        if (!password.equals(confirmPassword)) {
            model.addAttribute("errorMessage", "Passwords do not match.");
            model.addAttribute("token", token);
            return "reset-password";
        }

        boolean success = passwordResetService.resetPassword(token, password);
        if (!success) {
            model.addAttribute("errorMessage", "This reset link is invalid or has expired.");
            return "forgot-password";
        }

        model.addAttribute("statusMessage", "Your password has been reset. You can now log in.");
        return "login";
    }

    private String resolveBaseUrl(HttpServletRequest request) {
        if (configuredBaseUrl != null && !configuredBaseUrl.isBlank()) {
            return configuredBaseUrl.trim().replaceAll("/$", "");
        }

        String scheme = request.getHeader("X-Forwarded-Proto");
        if (scheme == null || scheme.isBlank()) {
            scheme = request.getScheme();
        }

        String host = request.getServerName();
        int port = request.getServerPort();
        boolean defaultPort = ("http".equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443);

        return scheme + "://" + host + (defaultPort ? "" : ":" + port);
    }
}
