package com.security.accounts.security.keys.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "rsa_key_pair")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RsaKeyPair {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @CreatedDate
    private LocalDateTime created;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
}
