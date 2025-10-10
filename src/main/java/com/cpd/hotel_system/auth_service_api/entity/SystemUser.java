package com.cpd.hotel_system.auth_service_api.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "system-user")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class SystemUser {
    @Id
    @Column(name = "user_id", length = 80, nullable = false)
    private String userId;

    @Column(name = "keycloak_id",  length = 80, nullable = false)
    private String keycloakId;

    @Column(name = "first_name", length = 100, nullable = false)
    private String firstName;

    @Column(name = "last_name", length = 100, nullable = false)
    private String lastName;

    @Column(name = "email", length = 100, nullable = false, unique = true)
    private String email;

    @Column(name = "contact", length = 20)
    private String contact;

    @Column(name = "is_active")
    private boolean isActive;

    @Column(name = "is_account_non_expired")
    private boolean isAccountNonExpired;

    @Column(name = "is_account_non_locked")
    private boolean isAccountNonLocked;

    @Column(name = "is_credentials_non_expired")
    private boolean isCredentialsNonExpired;

    @Column(name = "is_enabled")
    private boolean isEnabled;

    @Column(name = "is_email_verified")
    private boolean isEmailVerified;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @OneToOne(mappedBy = "systemUser")
    private Otp otp;

}
