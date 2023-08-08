package com.security.accounts.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.security.accounts.config.keys.KeyManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.Set;
import java.util.stream.Collectors;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
@Slf4j
public class AuthServerConfig {

    private final KeyManager keyManager;

    @Value("${url.login.page}")
    private String loginUrl;

    public AuthServerConfig(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {

//        http.authorizeHttpRequests(authz -> authz
//                .requestMatchers("/auth/user", "/clients").hasAuthority("SCOPE_admin"));

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Habilitamos el soporte para OpenID connect
        OAuth2AuthorizationServerConfigurer authz = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                // Se agrega página personalizada de consent (confirmar el acceso del cliente al resource server)
                //.authorizationEndpoint( authz -> authz.consentPage("/oauth2/consent"))
                // Se configura para hacer uso del flujo OpenID Connect por defecto
                .oidc(Customizer.withDefaults());
        http.securityMatchers(matchers -> matchers
                .requestMatchers(antMatcher("/oauth2/**"), authz.getEndpointsMatcher())
        );
        //Con las siguientes lineas de código se redirige a la página de login cuando nadie esta autenticado cuando
        //solicitamos un access token
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")))
                // Acá habilitamos al resource server para acceder a información del usuario
                .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));

        return http.build();
    }

//    @Bean
//    @Order(2)
//    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests( auth -> auth
//                        .requestMatchers("/auth/**", "/clients/**").permitAll()
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults());
//        http.csrf(AbstractHttpConfigurer::disable);
//        return http.build();
//    }


    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests( auhorize -> auhorize
                .requestMatchers("/login", "/error", "/auth/user/**", "/clients/**").permitAll()
                .anyRequest().authenticated()
        )

        // El siguiente formLogin redireccionará a la página de login desde el filtro del authorization server
        .formLogin( login -> login.loginPage("/login"));
        http.csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();
            if (context.getTokenType().getValue().equals("id_token")) {
                context.getClaims().claim("token_type", "access token");
                Set<String> roles = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context.getClaims().claim("roles", roles);
            }
        };
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
    }

    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        //RSAKey rsaKey = keyManager.generateRSAKey();
        RSAKey rsaKey = keyManager.getRSAKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
    }

    //Bean asociado a el uso de consent
//    @Bean
//    JdbcOAuth2AuthorizationConsentService consentService(DataSource dataSource, RegisteredClientRepository clientRepository) {
//        return new JdbcOAuth2AuthorizationConsentService(new JdbcTemplate(dataSource), clientRepository);
//    }

}
