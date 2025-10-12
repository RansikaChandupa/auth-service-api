package com.cpd.hotel_system.auth_service_api.repo;

import com.cpd.hotel_system.auth_service_api.entity.Otp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface OtpRepo extends JpaRepository<Otp, String> {
    @Query(value = "SELECT * FROM otp WHERE system_user_id=?1", nativeQuery = true)
    public Optional<Otp> findBySystemUserId(String id);
}
