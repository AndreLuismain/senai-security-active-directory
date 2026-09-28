package com.senai.security.ad.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        final String schemeName = "BasicAuth";
        return new OpenAPI()
            .info(new Info()
                .title("Active Directory Identity Management REST API")
                .version("1.0.0")
                .description("API REST para gestao automatizada de identidades no Active Directory via LDAP/LDAPS.")
                .contact(new Contact().name("Andre Luis & Equipe SENAI").email("andre.luis@corp.senai.local")))
            .addSecurityItem(new SecurityRequirement().addList(schemeName))
            .components(new Components()
                .addSecuritySchemes(schemeName,
                    new SecurityScheme()
                        .name(schemeName)
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("basic")
                        .description("Credenciais administrativas da API")));
    }
}
