package com.cpd.hotel_system.auth_service_api.repo;

import com.cpd.hotel_system.auth_service_api.entity.Otp;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OtpRepo extends JpaRepository<Otp, String> {

}
