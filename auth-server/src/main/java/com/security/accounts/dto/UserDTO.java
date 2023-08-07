package com.security.accounts.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDTO {

    private String id;
    @NotBlank(message = "Username is mandatory")
    @Size(min = 8, max = 32, message = "Invalid Username")
    private String username;
    @JsonIgnore
    @NotBlank
    @Size(min = 8, max = 32, message = "Invalid Username")
    private String password;
    private Set<String> roles;

}
