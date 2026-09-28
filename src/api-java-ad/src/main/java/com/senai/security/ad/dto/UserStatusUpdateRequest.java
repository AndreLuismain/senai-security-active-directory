package com.senai.security.ad.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Dados para alteracao do status do usuario no AD")
public class UserStatusUpdateRequest {

    @NotNull(message = "O estado 'enabled' deve ser informado (true ou false).")
    private Boolean enabled;

    private String reason;
}
