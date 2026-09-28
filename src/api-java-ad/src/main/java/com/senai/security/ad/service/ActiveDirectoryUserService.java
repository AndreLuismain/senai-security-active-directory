package com.senai.security.ad.service;

import com.senai.security.ad.dto.UserCreateRequest;
import com.senai.security.ad.dto.UserResponse;

import java.util.List;

public interface ActiveDirectoryUserService {
    UserResponse createUser(UserCreateRequest request);
    UserResponse findByUsername(String username);
    List<UserResponse> listUsers(String department);
    UserResponse updateUserStatus(String username, boolean enabled, String reason);
    UserResponse unlockUser(String username);
    void deleteUser(String username);
}
