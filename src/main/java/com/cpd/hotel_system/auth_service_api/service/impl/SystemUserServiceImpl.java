package com.cpd.hotel_system.auth_service_api.service.impl;

import com.cpd.hotel_system.auth_service_api.entity.Otp;
import com.cpd.hotel_system.auth_service_api.exception.BadRequestException;
import com.cpd.hotel_system.auth_service_api.config.KeycloakSecurityUtil;
import com.cpd.hotel_system.auth_service_api.dto.request.SystemUserRequestDto;
import com.cpd.hotel_system.auth_service_api.entity.SystemUser;
import com.cpd.hotel_system.auth_service_api.exception.DuplicateEntryException;
import com.cpd.hotel_system.auth_service_api.repo.OtpRepo;
import com.cpd.hotel_system.auth_service_api.repo.SystemUserRepo;
import com.cpd.hotel_system.auth_service_api.service.EmailService;
import com.cpd.hotel_system.auth_service_api.service.SystemUserService;
import com.cpd.hotel_system.auth_service_api.util.OtpGenerator;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;

import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
public class SystemUserServiceImpl implements SystemUserService {
    private final SystemUserRepo systemUserRepo;
    private final KeycloakSecurityUtil keycloakUtil;
    private final OtpRepo  otpRepo;
    private final OtpGenerator otpGenerator;
    private final EmailService  emailService;

    @Value("${keycloak.config.realm}")
    private String realm;

    @Override
    public void createUser(SystemUserRequestDto dto) throws IOException {
        if(dto.getFirstName() == null || dto.getFirstName().trim().isEmpty()){
            throw new BadRequestException("First name is required");
        }
        if(dto.getLastName() == null || dto.getLastName().trim().isEmpty()){
            throw new BadRequestException("Last name is required");
        }
        if(dto.getEmail() == null || dto.getEmail().trim().isEmpty()){
            throw new BadRequestException("Email is required");
        }
        String userId = "";
        String otp = "";
        Keycloak keycloak = null;

        UserRepresentation existingUser = null;
        keycloak = keycloakUtil.getKeycloakInstance();
        existingUser = keycloak.realm(realm).users().search(dto.getEmail()).stream().findFirst().orElse(null);

        if(existingUser != null){
            Optional<SystemUser> selectedUserFromAuthService = systemUserRepo.findByEmail(dto.getEmail());
            if(selectedUserFromAuthService.isEmpty()){
                keycloak.realm(realm).users().delete(existingUser.getId());
            }
            else{
                throw new DuplicateEntryException("Email already exists");
            }

        }
        else {
            Optional<SystemUser> selectedUserFromAuthService = systemUserRepo.findByEmail(dto.getEmail());
            if (selectedUserFromAuthService.isPresent()) {

                Optional<Otp> selectedOtp = otpRepo.findBySystemUserId(selectedUserFromAuthService.get().getUserId());
                if (selectedOtp.isPresent()){
                    otpRepo.deleteById(selectedOtp.get().getPropertyId());
                }
                systemUserRepo.deleteById(selectedUserFromAuthService.get().getUserId());

            }
        }
        UserRepresentation userRepresentation = mapUserRepo(dto, false, false);
        Response response = keycloak.realm(realm).users().create(userRepresentation);
        if(response.getStatus() == Response.Status.CREATED.getStatusCode()){
            RoleRepresentation userRole = keycloak.realm(realm).roles().get("user").toRepresentation();
            userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Arrays.asList(userRole));
            UserRepresentation createdUser = keycloak.realm(realm).users().get(userId).toRepresentation();
            SystemUser systemUser = SystemUser.builder()
                    .userId(userId)
                    .keycloakId(createdUser.getId())
                    .firstName(dto.getFirstName())
                    .lastName(dto.getLastName())
                    .email(dto.getEmail())
                    .contact(dto.getContact())
                    .isActive(false)
                    .isAccountNonExpired(true)
                    .isAccountNonLocked(true)
                    .isCredentialsNonExpired(true)
                    .isEnabled(false)
                    .isEmailVerified(false)
                    .createdAt(new Date().toInstant())
                    .updatedAt(new Date().toInstant())
                    .build();
            SystemUser savedUser = systemUserRepo.save(systemUser);
            Otp createdOtp = Otp.builder()
                    .propertyId(UUID.randomUUID().toString())
                    .code(otpGenerator.generateOtp(5))
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .isVerified(false)
                    .attempts(0)
                    .build();
            otpRepo.save(createdOtp);
            emailService.sendUserSignUpVerificationCode(dto.getEmail(), "Verify your email", createdOtp.getCode(), dto.getFirstName());

        }
    }

    @Override
    public void initializeHost(ArrayList<SystemUserRequestDto> users) throws IOException {
        for(SystemUserRequestDto dto : users){
            Optional<SystemUser> selectedUser = systemUserRepo.findByEmail(dto.getEmail());
            if(selectedUser.isPresent()){
                continue;
            }


            String userId = "";
            String otp = "";
            Keycloak keycloak = null;

            UserRepresentation existingUser = null;
            keycloak = keycloakUtil.getKeycloakInstance();
            existingUser = keycloak.realm(realm).users().search(dto.getEmail()).stream().findFirst().orElse(null);

            if(existingUser != null){
                Optional<SystemUser> selectedUserFromAuthService = systemUserRepo.findByEmail(dto.getEmail());
                if(selectedUserFromAuthService.isEmpty()){
                    keycloak.realm(realm).users().delete(existingUser.getId());
                }
                else{
                    throw new DuplicateEntryException("Email already exists");
                }

            }
            else {
                Optional<SystemUser> selectedUserFromAuthService = systemUserRepo.findByEmail(dto.getEmail());
                if (selectedUserFromAuthService.isPresent()) {

                    Optional<Otp> selectedOtp = otpRepo.findBySystemUserId(selectedUserFromAuthService.get().getUserId());
                    if (selectedOtp.isPresent()){
                        otpRepo.deleteById(selectedOtp.get().getPropertyId());
                    }
                    systemUserRepo.deleteById(selectedUserFromAuthService.get().getUserId());

                }
            }
            UserRepresentation userRepresentation = mapUserRepo(dto, true, true);
            Response response = keycloak.realm(realm).users().create(userRepresentation);
            if(response.getStatus() == Response.Status.CREATED.getStatusCode()){
                RoleRepresentation userRole = keycloak.realm(realm).roles().get("host").toRepresentation();
                userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Arrays.asList(userRole));
                UserRepresentation createdUser = keycloak.realm(realm).users().get(userId).toRepresentation();
                SystemUser systemUser = SystemUser.builder()
                        .userId(userId)
                        .keycloakId(createdUser.getId())
                        .firstName(dto.getFirstName())
                        .lastName(dto.getLastName())
                        .email(dto.getEmail())
                        .contact(dto.getContact())
                        .isActive(true)
                        .isAccountNonExpired(true)
                        .isAccountNonLocked(true)
                        .isCredentialsNonExpired(true)
                        .isEnabled(true)
                        .isEmailVerified(true)
                        .createdAt(new Date().toInstant())
                        .updatedAt(new Date().toInstant())
                        .build();
                SystemUser savedUser = systemUserRepo.save(systemUser);

                emailService.sendHostPassword(dto.getEmail(), "Access system by using the above password", dto.getPassword(), dto.getFirstName());

            }

        }
    }

    // The user, that needs to be stored in keycloak server
    private UserRepresentation mapUserRepo(SystemUserRequestDto dto, boolean isEmailVerified, boolean isEnabled){
        UserRepresentation user = new UserRepresentation();
        user.setEmail(dto.getEmail());
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setUsername(dto.getEmail());
        user.setEnabled(isEnabled);
        user.setEmailVerified(isEmailVerified);
        List<CredentialRepresentation> credList = new ArrayList<>();
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setTemporary(false);
        cred.setValue(dto.getPassword());
        credList.add(cred);
        user.setCredentials(credList);
        return user;
    }
}

