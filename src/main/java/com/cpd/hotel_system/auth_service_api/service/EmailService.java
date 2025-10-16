package com.cpd.hotel_system.auth_service_api.service;

import java.io.IOException;

public interface EmailService {
    public boolean sendUserSignUpVerificationCode(String toEmail, String subject, String otp,  String firstName) throws IOException;
    public boolean sendHostPassword(String toEmail, String subject, String password,  String firstName) throws IOException;
}
