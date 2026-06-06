package com.auth;

import org.springframework.boot.SpringApplication;

public class LocalApplication {

    public static void main(String[] args) {
        SpringApplication.from(AuthSpringApplication::main)
                .with(ContainersConfig.class)
                .run("--spring.profiles.active=local");
    }
}
