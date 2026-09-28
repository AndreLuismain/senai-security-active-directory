package com.senai.security.ad.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Representacao de dados de um usuario do Active Directory")
public class UserResponse {
    private String samAccountName;
    private String userPrincipalName;
    private String displayName;
    private String firstName;
    private String lastName;
    private String email;
    private String department;
    private String jobTitle;
    private String distinguishedName;
    private boolean enabled;
    private boolean locked;
    private Integer userAccountControl;
}
