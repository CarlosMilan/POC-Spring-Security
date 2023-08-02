package com.security.accounts.service;

import com.security.accounts.dto.ClientDTO;
import com.security.accounts.dto.MessageDTO;
import com.security.accounts.entity.Client;
import com.security.accounts.exception.ResourceNotFoundException;
import com.security.accounts.repository.ClientRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@AllArgsConstructor
public class ClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    public MessageDTO createClient(ClientDTO clientDTO) {
        Client client = clientFromDTO(clientDTO);
        clientRepository.save(client);
        return new MessageDTO("Client " + client.getClientId() + " created");
    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findById(UUID.fromString(id))
                .orElseThrow(() -> new ResourceNotFoundException("Client not found"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new ResourceNotFoundException("Client not found"));
        return Client.toRegisteredClient(client);
    }

    private Client clientFromDTO(ClientDTO clientDTO) {
        return Client.builder()
                .clientId(clientDTO.getClientId())
                .clientSecret(passwordEncoder.encode(clientDTO.getClientSecret()))
                .authenticationMethods(clientDTO.getAuthenticationMethods())
                .authorizationGrantTypes(clientDTO.getAuthorizationGrantTypes())
                .redirectUris(clientDTO.getRedirectUris())
                .scopes(clientDTO.getScopes())
                .requireProofKey(clientDTO.getRequireProofKey())
                .build();
    }
}
