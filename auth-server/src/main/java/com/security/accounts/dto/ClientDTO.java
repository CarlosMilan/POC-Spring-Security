package com.security.accounts.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ClientDTO {

    @NotBlank
    private String clientId;
    @NotBlank
    private String clientSecret;
    private Set<@NotNull ClientAuthenticationMethod> authenticationMethods;
    private Set<@NotNull AuthorizationGrantType> authorizationGrantTypes;
    private Set<@NotBlank String> redirectUris;
    private Set<@NotBlank String> scopes;
    @NotNull
    private Boolean requireProofKey;
}
