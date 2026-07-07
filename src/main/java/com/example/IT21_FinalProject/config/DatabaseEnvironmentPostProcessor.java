package com.example.IT21_FinalProject.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.HashMap;
import java.util.Map;

/**
 * Normalizes datasource properties before auto-configuration reads them.
 */
public class DatabaseEnvironmentPostProcessor implements EnvironmentPostProcessor {

    private static final String PROPERTY_SOURCE = "renderDatabaseProperties";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        DatabaseUrlResolver.ResolvedDatabase config = DatabaseUrlResolver.resolve(environment);

        Map<String, Object> properties = new HashMap<>();
        properties.put("spring.datasource.url", config.jdbcUrl());
        if (config.username() != null) {
            properties.put("spring.datasource.username", config.username());
        }
        properties.put("spring.datasource.password", config.password() != null ? config.password() : "");

        environment.getPropertySources().addFirst(new MapPropertySource(PROPERTY_SOURCE, properties));
    }
}
