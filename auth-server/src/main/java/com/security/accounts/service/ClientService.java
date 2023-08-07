package com.security.accounts.service;

import com.security.accounts.dto.ClientDTO;
import com.security.accounts.dto.ClientResponseDTO;
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

    public ClientResponseDTO getClientDetails(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new ResourceNotFoundException("Client not found"));

        return ClientResponseDTO.builder()
                .id(client.getId().toString())
                .authenticationMethods(client.getAuthenticationMethods())
                .authorizationGrantTypes(client.getAuthorizationGrantTypes())
                .clientId(client.getClientId())
                .redirectUris(client.getRedirectUris())
                .requireProofKey(client.getRequireProofKey())
                .scopes(client.getScopes())
                .build();
    }

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    public MessageDTO createClient(ClientDTO clientDTO) {
        Client client = clientFromDTO(clientDTO);
        clientRepository.save(client);
        return new MessageDTO("Client " + client.getClientId() + " created");
    }

    public MessageDTO updateClient(String id, ClientDTO clientDTO) {
        if (clientRepository.existsById(UUID.fromString(id))) {
            Client client = clientFromDTO(clientDTO);
            client.setId(UUID.fromString(id));
            clientRepository.save(client);
            return new MessageDTO("Client " + client.getClientId() + " updated");
        } else {
            throw new ResourceNotFoundException("Client not found");
        }
    }

    public void deleteClient(String id) {
        clientRepository.deleteById(UUID.fromString(id));
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
