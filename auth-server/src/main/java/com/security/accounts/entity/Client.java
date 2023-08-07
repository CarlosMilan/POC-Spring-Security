package com.security.accounts.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.io.Serializable;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "clients")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Client implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "client_id", unique = true)
    private String clientId;
    private String clientSecret;

    @ElementCollection(fetch = FetchType.EAGER) // Genera una tabla pero sin id
    private Set<ClientAuthenticationMethod> authenticationMethods;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<AuthorizationGrantType> authorizationGrantTypes;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> redirectUris;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> scopes;

    private Boolean requireProofKey;

    public static RegisteredClient toRegisteredClient(Client client) {
        RegisteredClient.Builder builder = RegisteredClient.withId(client.getClientId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientIdIssuedAt(new Date().toInstant())
                .clientAuthenticationMethods(am -> am.addAll(client.getAuthenticationMethods()))
                .authorizationGrantTypes(agt -> agt.addAll(client.getAuthorizationGrantTypes()))
                .redirectUris(ru -> ru.addAll(client.getRedirectUris()))
                .scopes(sc -> sc.addAll(client.getScopes()))
                .clientSettings(ClientSettings.builder().requireProofKey(client.getRequireProofKey()).build());

        return builder.build();
    }
}
