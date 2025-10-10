package com.cpd.hotel_system.auth_service_api.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "otp")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class Otp {
    @Id
    @Column(name = "property_id", length = 80, nullable = false)
    private String propertyId;

    @Column(name = "code", length = 80, nullable = false)
    private String code;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "is_verified")
    private boolean isVerified;

    @Column(name = "attempts")
    private Integer attempts;

    @OneToOne
    @JoinColumn(name = "system_user_id", nullable = false, unique = true)
    private SystemUser systemUser;
}
