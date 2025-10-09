package com.cpd.hotel_system.auth_service_api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class AuthServiceApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApiApplication.class, args);
	}

}
