package com.example.IT21_FinalProject.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Normalizes Render/Heroku-style DATABASE_URL values before DataSource auto-configuration.
 */
public class DatabaseEnvironmentPostProcessor implements EnvironmentPostProcessor {

    private static final String PROPERTY_SOURCE = "renderDatabaseProperties";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        Map<String, Object> properties = new HashMap<>();

        String dbHost = environment.getProperty("DB_HOST");
        String dbName = environment.getProperty("DB_NAME");
        boolean hasSplitDbConfig = isSet(dbHost) && isSet(dbName) && !dbHost.contains("://");

        if (hasSplitDbConfig) {
            // Prefer DB_* vars on Render — ignores a bad SPRING_DATASOURCE_URL override.
            String port = environment.getProperty("DB_PORT", "5432");
            properties.put("spring.datasource.url",
                    "jdbc:postgresql://" + dbHost.trim() + ":" + port + "/" + dbName.trim());
            if (isSet(environment.getProperty("DB_USER"))) {
                properties.put("spring.datasource.username", environment.getProperty("DB_USER").trim());
            }
            if (environment.getProperty("DB_PASSWORD") != null) {
                properties.put("spring.datasource.password", environment.getProperty("DB_PASSWORD"));
            }
        } else {
            String databaseUrl = environment.getProperty("DATABASE_URL");
            if (isSet(databaseUrl)) {
                applyParsedUrl(properties, databaseUrl);
            } else {
                String springUrl = firstNonBlank(
                        environment.getProperty("SPRING_DATASOURCE_URL"),
                        environment.getProperty("spring.datasource.url"));
                if (isSet(springUrl)
                        && (springUrl.startsWith("postgresql://") || springUrl.startsWith("postgres://"))) {
                    applyParsedUrl(properties, springUrl);
                } else if (isSet(springUrl) && !springUrl.startsWith("jdbc:")) {
                    properties.put("spring.datasource.url", "jdbc:" + springUrl);
                }
            }
        }

        if (!properties.isEmpty()) {
            environment.getPropertySources().addFirst(new MapPropertySource(PROPERTY_SOURCE, properties));
        }
    }

    private boolean isSet(String value) {
        return value != null && !value.isBlank();
    }

    private void applyParsedUrl(Map<String, Object> properties, String databaseUrl) {
        String normalized = databaseUrl.replace("postgres://", "postgresql://");
        URI uri = URI.create(normalized);

        String username = "postgres";
        String password = "";
        String userInfo = uri.getUserInfo();
        if (userInfo != null && !userInfo.isBlank()) {
            String[] parts = userInfo.split(":", 2);
            username = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            if (parts.length > 1) {
                password = URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }

        String path = uri.getPath() == null ? "" : uri.getPath();
        String jdbcUrl = "jdbc:postgresql://" + uri.getHost()
                + (uri.getPort() > 0 ? ":" + uri.getPort() : "")
                + path;

        properties.put("spring.datasource.url", jdbcUrl);
        properties.put("spring.datasource.username", username);
        properties.put("spring.datasource.password", password);
    }

    private String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        if (second != null && !second.isBlank()) {
            return second;
        }
        return null;
    }
}
