package com.senai.security.ad.controller;

import com.senai.security.ad.dto.ApiResponse;
import com.senai.security.ad.dto.UserCreateRequest;
import com.senai.security.ad.dto.UserResponse;
import com.senai.security.ad.dto.UserStatusUpdateRequest;
import com.senai.security.ad.service.ActiveDirectoryUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
@Tag(name = "Active Directory Users", description = "Endpoints de gestao e integracao LDAP no Active Directory")
public class ActiveDirectoryUserController {

    private final ActiveDirectoryUserService userService;

    public ActiveDirectoryUserController(ActiveDirectoryUserService userService) {
        this.userService = userService;
    }

    @PostMapping
    @Operation(summary = "Criar novo usuario no Active Directory")
    public ResponseEntity<ApiResponse<UserResponse>> createUser(@Valid @RequestBody UserCreateRequest request) {
        UserResponse response = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(ApiResponse.created("Usuario provisionado no Active Directory com sucesso.", response));
    }

    @GetMapping("/{username}")
    @Operation(summary = "Buscar usuario pelo logon sAMAccountName")
    public ResponseEntity<ApiResponse<UserResponse>> getUserByUsername(@PathVariable String username) {
        UserResponse response = userService.findByUsername(username);
        return ResponseEntity.ok(ApiResponse.success("Usuario localizado com sucesso.", response));
    }

    @GetMapping
    @Operation(summary = "Listar usuarios com filtro opcional por departamento")
    public ResponseEntity<ApiResponse<List<UserResponse>>> listUsers(@RequestParam(required = false) String department) {
        List<UserResponse> users = userService.listUsers(department);
        return ResponseEntity.ok(ApiResponse.success("Total de usuarios encontrados: " + users.size(), users));
    }

    @PatchMapping("/{username}/status")
    @Operation(summary = "Bloquear ou habilitar conta de usuario no AD")
    public ResponseEntity<ApiResponse<UserResponse>> updateUserStatus(
            @PathVariable String username,
            @Valid @RequestBody UserStatusUpdateRequest request) {
        UserResponse response = userService.updateUserStatus(username, request.getEnabled(), request.getReason());
        String statusText = Boolean.TRUE.equals(request.getEnabled()) ? "habilitada" : "bloqueada/suspensa";
        return ResponseEntity.ok(ApiResponse.success("Conta de usuario " + statusText + " com sucesso.", response));
    }

    @PostMapping("/{username}/unlock")
    @Operation(summary = "Desbloquear usuario (lockoutTime = 0)")
    public ResponseEntity<ApiResponse<UserResponse>> unlockUser(@PathVariable String username) {
        UserResponse response = userService.unlockUser(username);
        return ResponseEntity.ok(ApiResponse.success("Conta desbloqueada com sucesso.", response));
    }

    @DeleteMapping("/{username}")
    @Operation(summary = "Excluir usuario do Active Directory")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable String username) {
        userService.deleteUser(username);
        return ResponseEntity.ok(ApiResponse.success("Usuario removido do Active Directory.", null));
    }
}
