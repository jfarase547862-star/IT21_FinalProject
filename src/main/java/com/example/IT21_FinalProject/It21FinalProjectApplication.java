package com.example.IT21_FinalProject;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
public class It21FinalProjectApplication {

	public static void main(String[] args) {
		SpringApplication.run(It21FinalProjectApplication.class, args);
	}

}
