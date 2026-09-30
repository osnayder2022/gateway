package com.oconde.gateway.config.security.authentication;

import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import java.util.List;

@Component
public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager {
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    public JwtReactiveAuthenticationManager(JwtAuthenticationProvider jwtAuthenticationProvider) {
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {

        if (!(authentication instanceof BearerTokenAuthenticationToken bearerToken)) {
            return Mono.empty(); // No es un token JWT, pasamos al siguiente
        }

        String token = authentication.getCredentials().toString();

        if (jwtAuthenticationProvider.validateToken(token)) {
            String username = jwtAuthenticationProvider.getUsernameFromToken(token);

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    List.of() // Aquí podrías mapear roles si los extraes del token
            );
            return Mono.just(auth);
        }
        return Mono.empty();
    }
}
