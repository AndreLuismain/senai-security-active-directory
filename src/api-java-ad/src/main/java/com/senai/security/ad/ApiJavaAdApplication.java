package com.senai.security.ad;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Ponto de entrada da aplicacao Spring Boot de integracao com Active Directory.
 * TCC: Implementacao de Active Directory e politicas de grupo em ambientes corporativos e educacionais.
 */
@SpringBootApplication
public class ApiJavaAdApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiJavaAdApplication.class, args);
    }
}
