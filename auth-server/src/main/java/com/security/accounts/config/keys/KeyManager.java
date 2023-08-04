package com.security.accounts.config.keys;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Component
@Slf4j
public class KeyManager {

    @Value("${jwt.key.id}")
    private String keyId;

    @Value("${jwt.key.private}")
    private RSAPrivateKey privateKey;

    @Value("${jwt.key.public}")
    private RSAPublicKey publicKey;

    public RSAKey generateRSAKey() {
        KeyPair keyPair = generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    public RSAKey getRSAKey() {
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();
    }

    /*
    En este método lo que se hace es generar un par de claves pública-privada usando el algoritmo RSA.
    En este punto, lo que debe hacer el resource server para recuperar esta clave pública y asi verificar
    la firma del token es llamar al endpoint http://<host>:<port>/oauth2/jwks el cúal es un estándar. Estos
    endpoints se pueden consultar en el endpoint http://<host>:<port>/.well-known/oauth-authorization-server
    el cuál también es un estándar. Esto esta definido en el flujo OpenID.
    ES IMPORTANTE REMARCAR QUE ESTE MÉTODO GENERA EL PAR DE CLAVES AUTOMATICAMENTE AL MOMENTO DE INICIAR
    LA APLICACIÓN - NO RECOMENDABLE PARA ENTORNOS PRODUCTIVOS
     */
    private KeyPair generateKeyPair() {
        KeyPair keyPair;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            log.info(e.getMessage());
            throw new RuntimeException(e.getMessage());
        }

        return keyPair;
    }
}
