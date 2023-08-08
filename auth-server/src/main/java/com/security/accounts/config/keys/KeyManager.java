package com.security.accounts.config.keys;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
@Slf4j
public class KeyManager {

    @Value("${jwt.key.id}")
    private String keyId;

    @Value("${jwt.key.private}")
    private RSAPrivateKey privateKey;

    @Value("${jwt.key.public}")
    private RSAPublicKey publicKey;

    public RSAKey getRSAKey() {
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();
    }
}
