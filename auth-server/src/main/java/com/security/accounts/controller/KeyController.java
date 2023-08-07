package com.security.accounts.controller;

import com.security.accounts.security.keys.service.KeyPairService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
@RequestMapping("/key")
public class KeyController {

    private final KeyPairService keyPairService;

    @PostMapping("/generate")
    String generate() {
        return keyPairService.generateNewKeyPair();
    }

}
