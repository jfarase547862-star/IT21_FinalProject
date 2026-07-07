package com.example.IT21_FinalProject.config;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;

@Configuration
@org.springframework.boot.autoconfigure.AutoConfigureBefore(DataSourceAutoConfiguration.class)
public class RenderDataSourceConfig {

    @Bean
    @Primary
    public DataSource dataSource(Environment environment) {
        DatabaseUrlResolver.ResolvedDatabase config = DatabaseUrlResolver.resolve(environment);

        HikariDataSource dataSource = new HikariDataSource();
        dataSource.setJdbcUrl(config.jdbcUrl());
        if (config.username() != null) {
            dataSource.setUsername(config.username());
        }
        dataSource.setPassword(config.password() != null ? config.password() : "");
        return dataSource;
    }
}
