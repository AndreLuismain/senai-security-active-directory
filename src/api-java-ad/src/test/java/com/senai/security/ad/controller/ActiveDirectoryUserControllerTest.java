package com.senai.security.ad.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.senai.security.ad.dto.UserCreateRequest;
import com.senai.security.ad.dto.UserResponse;
import com.senai.security.ad.dto.UserStatusUpdateRequest;
import com.senai.security.ad.service.ActiveDirectoryUserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ActiveDirectoryUserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private ActiveDirectoryUserService userService;

    @Test
    @WithMockUser(username = "admin_api", roles = {"ADMIN"})
    @DisplayName("Deve criar um novo usuario no AD com sucesso")
    void shouldCreateUserSuccessfully() throws Exception {
        UserCreateRequest request = UserCreateRequest.builder()
            .samAccountName("andre.luis")
            .firstName("Andre")
            .lastName("Luis")
            .email("andre.luis@corp.senai.local")
            .department("TI")
            .jobTitle("Engenheiro de Seguranca")
            .initialPassword("S3cur3P@ssw0rd!2026")
            .mustChangePasswordOnLogon(false)
            .cannotChangePassword(true)
            .build();

        UserResponse mockResponse = UserResponse.builder()
            .samAccountName("andre.luis")
            .userPrincipalName("andre.luis@corp.senai.local")
            .displayName("Andre Luis")
            .email("andre.luis@corp.senai.local")
            .department("TI")
            .jobTitle("Engenheiro de Seguranca")
            .enabled(true)
            .locked(false)
            .userAccountControl(512)
            .build();

        when(userService.createUser(any(UserCreateRequest.class))).thenReturn(mockResponse);

        mockMvc.perform(post("/api/v1/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.status").value(201))
            .andExpect(jsonPath("$.data.samAccountName").value("andre.luis"))
            .andExpect(jsonPath("$.data.enabled").value(true));
    }

    @Test
    @WithMockUser(username = "admin_api", roles = {"ADMIN"})
    @DisplayName("Deve suspender/bloquear um usuario no AD")
    void shouldUpdateUserStatusToDisabled() throws Exception {
        UserStatusUpdateRequest updateReq = UserStatusUpdateRequest.builder()
            .enabled(false)
            .reason("Bloqueio preventivo")
            .build();

        UserResponse mockResponse = UserResponse.builder()
            .samAccountName("andre.luis")
            .enabled(false)
            .userAccountControl(514)
            .build();

        when(userService.updateUserStatus(eq("andre.luis"), eq(false), any())).thenReturn(mockResponse);

        mockMvc.perform(patch("/api/v1/users/andre.luis/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateReq)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.samAccountName").value("andre.luis"))
            .andExpect(jsonPath("$.data.enabled").value(false));
    }

    @Test
    @WithMockUser(username = "admin_api", roles = {"ADMIN"})
    @DisplayName("Deve listar usuarios filtrando por departamento")
    void shouldListUsersByDepartment() throws Exception {
        UserResponse user = UserResponse.builder()
            .samAccountName("andre.luis")
            .department("TI")
            .enabled(true)
            .build();

        when(userService.listUsers("TI")).thenReturn(List.of(user));

        mockMvc.perform(get("/api/v1/users?department=TI"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data[0].samAccountName").value("andre.luis"))
            .andExpect(jsonPath("$.data[0].department").value("TI"));
    }

    @Test
    @DisplayName("Deve rejeitar requisicoes sem autenticacao HTTP Basic com 401")
    void shouldRejectUnauthenticatedRequests() throws Exception {
        mockMvc.perform(get("/api/v1/users"))
            .andExpect(status().isUnauthorized());
    }
}
