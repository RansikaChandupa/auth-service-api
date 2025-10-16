package com.cpd.hotel_system.auth_service_api.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class EntryNotFoundException extends RuntimeException{
    public EntryNotFoundException(String message){
        super(message);
    }
}
