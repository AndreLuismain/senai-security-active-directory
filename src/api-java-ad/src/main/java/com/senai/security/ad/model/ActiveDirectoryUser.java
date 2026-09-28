package com.senai.security.ad.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ActiveDirectoryUser {
    private String distinguishedName;
    private String samAccountName;
    private String userPrincipalName;
    private String commonName;
    private String givenName;
    private String surname;
    private String displayName;
    private String email;
    private String department;
    private String title;
    private Integer userAccountControl;
    private Long lockoutTime;

    public boolean isEnabled() {
        if (userAccountControl == null) {
            return false;
        }
        return (userAccountControl & 0x0002) == 0;
    }

    public boolean isLocked() {
        return lockoutTime != null && lockoutTime > 0;
    }
}
