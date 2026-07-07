package com.example.IT21_FinalProject.config;

import org.springframework.core.env.Environment;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

final class DatabaseUrlResolver {

    private DatabaseUrlResolver() {
    }

    static ResolvedDatabase resolve(Environment environment) {
        String dbHost = trimToNull(environment.getProperty("DB_HOST"));
        String dbName = trimToNull(environment.getProperty("DB_NAME"));

        if (dbHost != null && dbName != null) {
            if (dbHost.contains("://")) {
                return fromPostgresUrl(dbHost, environment);
            }
            String port = environment.getProperty("DB_PORT", "5432");
            return new ResolvedDatabase(
                    "jdbc:postgresql://" + dbHost + ":" + port + "/" + dbName,
                    trimToNull(environment.getProperty("DB_USER")),
                    environment.getProperty("DB_PASSWORD", ""));
        }

        String databaseUrl = firstNonBlank(
                environment.getProperty("DATABASE_URL"),
                environment.getProperty("SPRING_DATASOURCE_URL"));
        if (databaseUrl != null) {
            return fromPostgresUrl(databaseUrl, environment);
        }

        String springUrl = trimToNull(environment.getProperty("spring.datasource.url"));
        if (springUrl != null) {
            if (springUrl.startsWith("jdbc:")) {
                return new ResolvedDatabase(
                        springUrl,
                        trimToNull(environment.getProperty("spring.datasource.username")),
                        environment.getProperty("spring.datasource.password", ""));
            }
            return fromPostgresUrl(springUrl, environment);
        }

        return new ResolvedDatabase(
                "jdbc:postgresql://localhost:5432/it21_db",
                "postgres",
                "123456");
    }

    private static ResolvedDatabase fromPostgresUrl(String databaseUrl, Environment environment) {
        String normalized = databaseUrl.replace("postgres://", "postgresql://");
        if (normalized.startsWith("jdbc:")) {
            normalized = normalized.substring("jdbc:".length());
        }

        URI uri = URI.create(normalized);
        String username = trimToNull(environment.getProperty("DB_USER"));
        String password = environment.getProperty("DB_PASSWORD");
        String userInfo = uri.getUserInfo();

        if (userInfo != null && !userInfo.isBlank()) {
            String[] parts = userInfo.split(":", 2);
            if (username == null) {
                username = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            }
            if (password == null || password.isBlank()) {
                password = parts.length > 1
                        ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8)
                        : "";
            }
        }

        if (username == null) {
            username = trimToNull(environment.getProperty("spring.datasource.username"));
        }
        if (password == null) {
            password = environment.getProperty("spring.datasource.password", "");
        }

        String path = uri.getPath() == null ? "" : uri.getPath();
        String jdbcUrl = "jdbc:postgresql://" + uri.getHost()
                + (uri.getPort() > 0 ? ":" + uri.getPort() : "")
                + path;

        return new ResolvedDatabase(jdbcUrl, username, password);
    }

    private static String firstNonBlank(String first, String second) {
        String a = trimToNull(first);
        if (a != null) {
            return a;
        }
        return trimToNull(second);
    }

    private static String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    record ResolvedDatabase(String jdbcUrl, String username, String password) {
    }
}
