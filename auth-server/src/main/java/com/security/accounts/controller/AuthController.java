package com.security.accounts.controller;

import com.security.accounts.dto.MessageDTO;
import com.security.accounts.dto.UserDTO;
import com.security.accounts.service.UserService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/user")
@AllArgsConstructor
public class AuthController {

    private final UserService userService;

    @GetMapping("/{username}")
    public ResponseEntity<UserDTO> getUser(@PathVariable String username) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(userService.getUserDetails(username));
    }

    @PostMapping
    public ResponseEntity<MessageDTO> createUser(@RequestBody @Valid UserDTO userDTO) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(userService.createUser(userDTO));
    }

    @PutMapping
    public ResponseEntity<MessageDTO> updateUser(@RequestBody @Valid UserDTO userDTO) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(userService.updateUser(userDTO));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<MessageDTO> deleteUser(@PathVariable String id) {
        return ResponseEntity
                .status(HttpStatus.NO_CONTENT)
                .body(userService.deleteUser(id));
    }



}
