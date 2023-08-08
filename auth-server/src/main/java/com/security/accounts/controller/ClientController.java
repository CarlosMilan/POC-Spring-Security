package com.security.accounts.controller;

import com.security.accounts.dto.ClientDTO;
import com.security.accounts.dto.ClientResponseDTO;
import com.security.accounts.dto.MessageDTO;
import com.security.accounts.service.ClientService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/clients")
public class ClientController {

    private final ClientService clientService;

    @PostMapping
    public ResponseEntity<MessageDTO> createClient(@RequestBody @Valid ClientDTO clientDTO) {
        return ResponseEntity.status(HttpStatus.CREATED).body(clientService.createClient(clientDTO));
    }

    @GetMapping("/{clientId}")
    public ResponseEntity<ClientResponseDTO> getClientDetails(@PathVariable String clientId) {
        return ResponseEntity.ok().body(clientService.getClientDetails(clientId));
    }

    @PutMapping("/{id}")
    public ResponseEntity<MessageDTO> updateClient(@PathVariable String id, @RequestBody @Valid ClientDTO clientDTO) {
        return ResponseEntity.status(HttpStatus.OK)
                .body(clientService.updateClient(id, clientDTO));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteClient(@PathVariable String id) {
        clientService.deleteClient(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }


}
