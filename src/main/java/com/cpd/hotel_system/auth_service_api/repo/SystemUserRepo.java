package com.cpd.hotel_system.auth_service_api.repo;

import com.cpd.hotel_system.auth_service_api.entity.SystemUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SystemUserRepo extends JpaRepository<SystemUser, String> {
    public Optional<SystemUser> findByEmail(String email);
}
