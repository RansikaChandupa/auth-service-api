package com.cpd.hotel_system.auth_service_api.service;

import com.cpd.hotel_system.auth_service_api.dto.request.SystemUserRequestDto;

import java.io.IOException;

import java.util.List;

public interface SystemUserService {
    public void createUser(SystemUserRequestDto dto) throws IOException;
    public void initializeHost(List<SystemUserRequestDto> users) throws IOException;
    public void resend(String email, String type);
    public void forgotPasswordSendVerificationCode(String email);

}
