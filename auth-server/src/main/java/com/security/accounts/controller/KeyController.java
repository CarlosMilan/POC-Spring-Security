package com.security.accounts.controller;

import com.security.accounts.security.keys.service.KeyPairService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class KeyController {

    private final KeyPairService keyPairService;

    @PostMapping("/test")
    String generate() {
        return keyPairService.generateNewKeyPair();
    }

}
