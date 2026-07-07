package com.example.IT21_FinalProject.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Component
public class SessionAuthenticationFilter extends OncePerRequestFilter {

    private final JdbcTemplate jdbcTemplate;

    public SessionAuthenticationFilter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean needsSessionBridge = authentication == null || authentication instanceof AnonymousAuthenticationToken;
        if (needsSessionBridge) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                Object email = session.getAttribute("userEmail");
                Object roleId = session.getAttribute("userRole");
                if (email instanceof String userEmail && roleId instanceof String role) {
                    try {
                        Map<String, Object> row = jdbcTemplate.queryForMap(
                                "SELECT email, password, role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
                                userEmail);
                        String resolvedRole = (String) row.getOrDefault("role_id", role);
                        String authority = switch (resolvedRole) {
                            case "ROL001" -> "ROLE_ADMIN";
                            case "ROL004" -> "ROLE_SECURITY_ANALYST";
                            default -> "ROLE_SIGNER";
                        };
                        var principal = User.withUsername(userEmail)
                                .password((String) row.getOrDefault("password", ""))
                                .authorities(authority)
                                .build();
                        var authenticated = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
                        authenticated.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authenticated);
                    } catch (org.springframework.dao.EmptyResultDataAccessException ignored) {
                        SecurityContextHolder.clearContext();
                    }
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
