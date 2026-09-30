package com.oconde.gateway.config.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.scheduler.Schedulers;
import reactor.core.publisher.Mono;

@Component
public class LdapReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    private final LdapAuthenticationProvider provider;

    // Inyección por constructor del LdapContextSource configurado por Spring
    // Es la dependencia que contiene la configuración de conexión al servidor
    // LDAP (URL, puerto, credenciales del administrador, etc.). Spring la inyecta automáticamente.
    public LdapReactiveAuthenticationManager(LdapContextSource contextSource) {
        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        // Configura aquí tu patrón de búsqueda (DN)
        authenticator.setUserDnPatterns(new String[]{"uid={0},ou=people"});

        this.provider = new LdapAuthenticationProvider(authenticator);
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        // Aprovechamos Pattern Matching de JDK 21
        if (!(authentication instanceof UsernamePasswordAuthenticationToken token)) {
            return Mono.empty();
        }

        return Mono.fromCallable(() -> {
            // Delegamos la lógica LDAP bloqueante al provider estándar de Spring
            // Si falla, lanzará una AuthenticationException
            return provider.authenticate(token);
        }).subscribeOn(Schedulers.boundedElastic());
    }
}