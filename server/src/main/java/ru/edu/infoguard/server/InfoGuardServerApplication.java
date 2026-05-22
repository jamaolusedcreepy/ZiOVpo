package ru.edu.infoguard.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class InfoGuardServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(InfoGuardServerApplication.class, args);
	}

}
