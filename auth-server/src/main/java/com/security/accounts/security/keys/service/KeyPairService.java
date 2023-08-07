package com.security.accounts.security.keys.service;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.security.accounts.config.keys.KeyManager;
import com.security.accounts.exception.KeyPairException;
import com.security.accounts.security.keys.entity.RsaKeyPair;
import com.security.accounts.security.keys.repository.RsaKeyPairRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
@Slf4j
public class KeyPairService implements JWKSource<SecurityContext>, OAuth2TokenCustomizer<JwtEncodingContext> {

    private final RsaKeyPairRepository rsaKeyPairRepository;

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
        List<RsaKeyPair> keyPairs = this.rsaKeyPairRepository.findAll();
        List<JWK> result = new ArrayList<>(keyPairs.size());

        keyPairs.forEach(kp -> {
            RSAKey rsaKey = new RSAKey.Builder(kp.getPublicKey())
                    .privateKey(kp.getPrivateKey())
                    .keyID(kp.getId().toString())
                    .build();

            if (jwkSelector.getMatcher().matches(rsaKey)) {
                result.add(rsaKey);
            }
        });
        return result;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        List<RsaKeyPair> keyPairs = this.rsaKeyPairRepository.findAll();
        String kid = keyPairs.get(keyPairs.size()-1).getId().toString();
        context.getJwsHeader().keyId(kid);

        Authentication principal = context.getPrincipal();
        if (context.getTokenType().getValue().equals("id_token")) {
            context.getClaims().claim("token_type", "access token");
            Set<String> roles = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            context.getClaims().claim("roles", roles);
        }
    }

    public String generateNewKeyPair() {
        RsaKeyPair rsaKeyPair = new RsaKeyPair();
        KeyPair keyPair = createKeyPair();
        rsaKeyPair.setId(UUID.randomUUID());
        rsaKeyPair.setPublicKey((RSAPublicKey) keyPair.getPublic());
        rsaKeyPair.setPrivateKey((RSAPrivateKey) keyPair.getPrivate());

        return rsaKeyPairRepository.save(rsaKeyPair).getId().toString();
    }

    private KeyPair createKeyPair() {
        KeyPair keyPair;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            log.info(e.getMessage());
            throw new KeyPairException(e.getMessage());
        }

        return keyPair;
    }
}
