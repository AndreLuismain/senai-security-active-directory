package com.senai.security.ad.service.impl;

import com.senai.security.ad.dto.UserCreateRequest;
import com.senai.security.ad.dto.UserResponse;
import com.senai.security.ad.exception.ActiveDirectoryOperationException;
import com.senai.security.ad.exception.UserAlreadyExistsException;
import com.senai.security.ad.exception.UserNotFoundException;
import com.senai.security.ad.model.ActiveDirectoryUser;
import com.senai.security.ad.service.ActiveDirectoryUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.query.SearchScope;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.stereotype.Service;

import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.LdapName;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ActiveDirectoryUserServiceImpl implements ActiveDirectoryUserService {

    private static final Logger logger = LoggerFactory.getLogger(ActiveDirectoryUserServiceImpl.class);

    private static final int UF_ACCOUNTDISABLE = 0x0002;
    private static final int UF_NORMAL_ACCOUNT = 0x0200;

    private final LdapTemplate ldapTemplate;

    @Value("${app.ldap.search-base:OU=SenaiCorp}")
    private String searchBase;

    @Value("${app.ldap.default-user-ou:OU=Alunos,OU=Educacional,OU=SenaiCorp,DC=corp,DC=senai,DC=local}")
    private String defaultUserOu;

    @Value("${app.ldap.upn-domain:corp.senai.local}")
    private String upnDomain;

    public ActiveDirectoryUserServiceImpl(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    @Override
    public UserResponse createUser(UserCreateRequest request) {
        logger.info("Criando usuario no Active Directory: {}", request.getSamAccountName());

        if (userExists(request.getSamAccountName())) {
            throw new UserAlreadyExistsException("Usuario com login '" + request.getSamAccountName() + "' ja existe.");
        }

        String targetOu = (request.getTargetOu() != null && !request.getTargetOu().isBlank())
            ? request.getTargetOu().trim()
            : defaultUserOu;

        String displayName = request.getFirstName() + " " + request.getLastName();
        String upn = request.getSamAccountName() + "@" + upnDomain;

        try {
            LdapName userDn = LdapNameBuilder.newInstance(targetOu)
                .add("CN", displayName)
                .build();

            Attributes attributes = new BasicAttributes(true);

            Attribute objectClass = new BasicAttribute("objectClass");
            objectClass.add("top");
            objectClass.add("person");
            objectClass.add("organizationalPerson");
            objectClass.add("user");
            attributes.put(objectClass);

            attributes.put("cn", displayName);
            attributes.put("sAMAccountName", request.getSamAccountName());
            attributes.put("userPrincipalName", upn);
            attributes.put("givenName", request.getFirstName());
            attributes.put("sn", request.getLastName());
            attributes.put("displayName", displayName);
            attributes.put("mail", request.getEmail());
            attributes.put("department", request.getDepartment());

            if (request.getJobTitle() != null && !request.getJobTitle().isBlank()) {
                attributes.put("title", request.getJobTitle());
            }

            attributes.put("userAccountControl", Integer.toString(UF_NORMAL_ACCOUNT));

            if (Boolean.TRUE.equals(request.getMustChangePasswordOnLogon())) {
                attributes.put("pwdLastSet", "0");
            } else {
                attributes.put("pwdLastSet", "-1");
            }

            byte[] encodedPassword = encodeActiveDirectoryPassword(request.getInitialPassword());
            attributes.put(new BasicAttribute("unicodePwd", encodedPassword));

            ldapTemplate.bind(userDn, null, attributes);
            logger.info("Usuario '{}' criado com sucesso.", request.getSamAccountName());

            return findByUsername(request.getSamAccountName());
        } catch (Exception ex) {
            logger.error("Erro ao criar usuario '{}': {}", request.getSamAccountName(), ex.getMessage(), ex);
            throw new ActiveDirectoryOperationException("Erro ao criar usuario no AD: " + ex.getMessage(), ex);
        }
    }

    @Override
    public UserResponse findByUsername(String username) {
        List<ActiveDirectoryUser> users = ldapTemplate.search(
            LdapQueryBuilder.query()
                .base(searchBase)
                .searchScope(SearchScope.SUBTREE)
                .where("objectClass").is("user")
                .and("sAMAccountName").is(username),
            adUserAttributesMapper()
        );

        if (users.isEmpty()) {
            throw new UserNotFoundException("Usuario '" + username + "' nao encontrado.");
        }

        return mapToResponse(users.get(0));
    }

    @Override
    public List<UserResponse> listUsers(String department) {
        LdapQueryBuilder query = LdapQueryBuilder.query()
            .base(searchBase)
            .searchScope(SearchScope.SUBTREE)
            .where("objectClass").is("user");

        if (department != null && !department.isBlank()) {
            query.and("department").is(department.trim());
        }

        return ldapTemplate.search(query, adUserAttributesMapper())
            .stream()
            .map(this::mapToResponse)
            .collect(Collectors.toList());
    }

    @Override
    public UserResponse updateUserStatus(String username, boolean enabled, String reason) {
        ActiveDirectoryUser user = findDomainUser(username)
            .orElseThrow(() -> new UserNotFoundException("Usuario '" + username + "' nao encontrado."));

        int currentUac = user.getUserAccountControl() != null ? user.getUserAccountControl() : UF_NORMAL_ACCOUNT;
        int newUac = enabled ? (currentUac & ~UF_ACCOUNTDISABLE) : (currentUac | UF_ACCOUNTDISABLE);

        try {
            ModificationItem[] mods = new ModificationItem[]{
                new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                    new BasicAttribute("userAccountControl", Integer.toString(newUac)))
            };

            LdapName dn = LdapUtils.newLdapName(user.getDistinguishedName());
            ldapTemplate.modifyAttributes(dn, mods);
            return findByUsername(username);
        } catch (Exception ex) {
            throw new ActiveDirectoryOperationException("Falha ao atualizar status da conta: " + ex.getMessage(), ex);
        }
    }

    @Override
    public UserResponse unlockUser(String username) {
        ActiveDirectoryUser user = findDomainUser(username)
            .orElseThrow(() -> new UserNotFoundException("Usuario '" + username + "' nao encontrado."));

        try {
            ModificationItem[] mods = new ModificationItem[]{
                new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("lockoutTime", "0"))
            };
            LdapName dn = LdapUtils.newLdapName(user.getDistinguishedName());
            ldapTemplate.modifyAttributes(dn, mods);
            return findByUsername(username);
        } catch (Exception ex) {
            throw new ActiveDirectoryOperationException("Falha ao desbloquear conta: " + ex.getMessage(), ex);
        }
    }

    @Override
    public void deleteUser(String username) {
        ActiveDirectoryUser user = findDomainUser(username)
            .orElseThrow(() -> new UserNotFoundException("Usuario '" + username + "' nao encontrado."));

        try {
            LdapName dn = LdapUtils.newLdapName(user.getDistinguishedName());
            ldapTemplate.unbind(dn);
        } catch (Exception ex) {
            throw new ActiveDirectoryOperationException("Falha ao excluir usuario: " + ex.getMessage(), ex);
        }
    }

    private boolean userExists(String username) {
        List<String> results = ldapTemplate.search(
            LdapQueryBuilder.query()
                .base(searchBase)
                .searchScope(SearchScope.SUBTREE)
                .where("objectClass").is("user")
                .and("sAMAccountName").is(username),
            (AttributesMapper<String>) attrs -> getAttributeValue(attrs, "sAMAccountName")
        );
        return !results.isEmpty();
    }

    private Optional<ActiveDirectoryUser> findDomainUser(String username) {
        List<ActiveDirectoryUser> users = ldapTemplate.search(
            LdapQueryBuilder.query()
                .base(searchBase)
                .searchScope(SearchScope.SUBTREE)
                .where("objectClass").is("user")
                .and("sAMAccountName").is(username),
            adUserAttributesMapper()
        );
        return users.stream().findFirst();
    }

    private byte[] encodeActiveDirectoryPassword(String rawPassword) {
        return (""" + rawPassword + """).getBytes(StandardCharsets.UTF_16LE);
    }

    private AttributesMapper<ActiveDirectoryUser> adUserAttributesMapper() {
        return attrs -> ActiveDirectoryUser.builder()
            .samAccountName(getAttributeValue(attrs, "sAMAccountName"))
            .userPrincipalName(getAttributeValue(attrs, "userPrincipalName"))
            .commonName(getAttributeValue(attrs, "cn"))
            .givenName(getAttributeValue(attrs, "givenName"))
            .surname(getAttributeValue(attrs, "sn"))
            .displayName(getAttributeValue(attrs, "displayName"))
            .email(getAttributeValue(attrs, "mail"))
            .department(getAttributeValue(attrs, "department"))
            .title(getAttributeValue(attrs, "title"))
            .distinguishedName(getAttributeValue(attrs, "distinguishedName"))
            .userAccountControl(parseSafeInt(getAttributeValue(attrs, "userAccountControl")))
            .lockoutTime(parseSafeLong(getAttributeValue(attrs, "lockoutTime")))
            .build();
    }

    private Integer parseSafeInt(String s) {
        if (s == null) return null;
        try { return Integer.parseInt(s); } catch (Exception e) { return null; }
    }

    private Long parseSafeLong(String s) {
        if (s == null) return null;
        try { return Long.parseLong(s); } catch (Exception e) { return null; }
    }

    private String getAttributeValue(Attributes attrs, String attrId) {
        Attribute attr = attrs.get(attrId);
        if (attr == null) return null;
        try {
            Object val = attr.get();
            return val != null ? val.toString() : null;
        } catch (NamingException e) {
            return null;
        }
    }

    private UserResponse mapToResponse(ActiveDirectoryUser user) {
        return UserResponse.builder()
            .samAccountName(user.getSamAccountName())
            .userPrincipalName(user.getUserPrincipalName())
            .displayName(user.getDisplayName())
            .firstName(user.getGivenName())
            .lastName(user.getSurname())
            .email(user.getEmail())
            .department(user.getDepartment())
            .jobTitle(user.getTitle())
            .distinguishedName(user.getDistinguishedName())
            .enabled(user.isEnabled())
            .locked(user.isLocked())
            .userAccountControl(user.getUserAccountControl())
            .build();
    }
}
