package com.example.IT21_FinalProject.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Map;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(JdbcTemplate jdbcTemplate) {
        return username -> {
            try {
                Map<String, Object> row = jdbcTemplate.queryForMap(
                    "SELECT email, password, role_id FROM \"user\" WHERE LOWER(email) = LOWER(?)",
                    username);
                String roleId = (String) row.get("role_id");
                String authority = switch (roleId) {
                    case "ROL001" -> "ROLE_ADMIN";
                    case "ROL004" -> "ROLE_SECURITY_ANALYST";
                    default -> "ROLE_SIGNER";
                };
                return User.withUsername((String) row.get("email"))
                    .password((String) row.get("password"))
                    .authorities(authority)
                    .build();
            } catch (org.springframework.dao.EmptyResultDataAccessException ex) {
                throw new UsernameNotFoundException("User not found: " + username);
            }
        };
    }

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, SessionAuthenticationFilter sessionAuthenticationFilter) throws Exception {
        http
            .csrf(csrf -> csrf.ignoringRequestMatchers(
                    "/api/**", "/signer/api/**", "/analyst/api/**", "/verify", "/analyst/verify",
                    "/forgot-password", "/reset-password", "/signup"))
            .addFilterBefore(sessionAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/", "/login", "/signup", "/forgot-password", "/reset-password", "/css/**", "/js/**", "/images/**", "/error").permitAll()
                .requestMatchers(HttpMethod.POST, "/login", "/signup", "/forgot-password", "/reset-password").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/signer/api/documents/upload").permitAll()
                .requestMatchers("/signer/api/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/logs/**").hasAnyRole("ADMIN", "SECURITY_ANALYST")
                .requestMatchers("/api/dashboard/**").hasRole("ADMIN")
                .requestMatchers("/api/documents/**").authenticated()
                .anyRequest().permitAll())
            .formLogin(form -> form.disable())
            .logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/login?message=Logged+out+successfully.").permitAll());

        return http.build();
    }
}
