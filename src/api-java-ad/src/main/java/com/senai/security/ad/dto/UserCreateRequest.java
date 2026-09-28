package com.senai.security.ad.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Dados para criacao de nova identidade no Active Directory")
public class UserCreateRequest {

    @NotBlank(message = "O login sAMAccountName e obrigatorio.")
    @Size(min = 3, max = 20, message = "O sAMAccountName deve ter entre 3 e 20 caracteres.")
    @Pattern(regexp = "^[a-zA-Z0-9._-]+$", message = "O sAMAccountName deve conter apenas letras, numeros, pontos, sublinhados ou hifens.")
    private String samAccountName;

    @NotBlank(message = "O primeiro nome e obrigatorio.")
    @Size(min = 2, max = 50)
    private String firstName;

    @NotBlank(message = "O sobrenome e obrigatorio.")
    @Size(min = 2, max = 50)
    private String lastName;

    @NotBlank(message = "O e-mail e obrigatorio.")
    @Email(message = "O e-mail deve ser valido.")
    private String email;

    @NotBlank(message = "O departamento e obrigatorio.")
    private String department;

    private String jobTitle;

    @NotBlank(message = "A senha inicial e obrigatoria.")
    @Size(min = 8, max = 64)
    private String initialPassword;

    private String targetOu;

    @Builder.Default
    private Boolean mustChangePasswordOnLogon = false;

    @Builder.Default
    private Boolean cannotChangePassword = true;
}
