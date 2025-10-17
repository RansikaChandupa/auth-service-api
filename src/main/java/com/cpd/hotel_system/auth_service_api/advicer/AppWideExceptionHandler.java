package com.cpd.hotel_system.auth_service_api.advicer;

import com.cpd.hotel_system.auth_service_api.exception.BadRequestException;
import com.cpd.hotel_system.auth_service_api.exception.EntryNotFoundException;
import com.cpd.hotel_system.auth_service_api.exception.UnAuthorizedException;
import com.cpd.hotel_system.auth_service_api.util.StandardResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;

public class AppWideExceptionHandler {
    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<StandardResponseDto> handleBadRequestException(BadRequestException ex) {
        return new ResponseEntity<StandardResponseDto>(
                new StandardResponseDto(400,ex.getMessage(),ex),
                HttpStatus.BAD_REQUEST
        );
    }
    @ExceptionHandler(EntryNotFoundException.class)
    public ResponseEntity<StandardResponseDto> handleEntryNotFoundException(EntryNotFoundException ex) {
        return new ResponseEntity<StandardResponseDto>(
                new StandardResponseDto(404,ex.getMessage(),ex),
                HttpStatus.NOT_FOUND
        );
    }
    @ExceptionHandler(UnAuthorizedException.class)
    public ResponseEntity<StandardResponseDto> handleUnAuthorizedException(UnAuthorizedException ex) {
        return new ResponseEntity<StandardResponseDto>(
                new StandardResponseDto(401,ex.getMessage(),ex),
                HttpStatus.UNAUTHORIZED
        );
    }

}
