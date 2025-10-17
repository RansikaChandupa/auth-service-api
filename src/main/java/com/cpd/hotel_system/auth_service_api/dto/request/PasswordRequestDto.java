package com.cpd.hotel_system.auth_service_api.dto.request;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PasswordRequestDto {
    private String email;
    private String password;
    private String code;
}
