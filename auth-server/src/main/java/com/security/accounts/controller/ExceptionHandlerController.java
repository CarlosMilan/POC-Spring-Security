package com.security.accounts.controller;

import com.security.accounts.dto.ErrorDTO;
import com.security.accounts.exception.KeyPairException;
import com.security.accounts.exception.ResourceNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.sql.Timestamp;
import java.util.Date;

@ControllerAdvice
public class ExceptionHandlerController {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorDTO> exceptionHandler(Exception e) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorDTO.builder()
                        .timestamp(new Timestamp(new Date().getTime()))
                        .detail("Internal Server Error")
                        .code(HttpStatus.INTERNAL_SERVER_ERROR.value())
                        .build());
    }

    @ExceptionHandler(KeyPairException.class)
    public ResponseEntity<ErrorDTO> keyPairExceptionHandler(KeyPairException e) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorDTO.builder()
                        .timestamp(new Timestamp(new Date().getTime()))
                        .detail(e.getMessage())
                        .code(HttpStatus.INTERNAL_SERVER_ERROR.value())
                        .build());
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorDTO> resourceNotFoundExceptionHandler(ResourceNotFoundException e) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ErrorDTO.builder()
                        .timestamp(new Timestamp(new Date().getTime()))
                        .detail(e.getMessage())
                        .code(HttpStatus.BAD_REQUEST.value())
                        .build());
    }


}
