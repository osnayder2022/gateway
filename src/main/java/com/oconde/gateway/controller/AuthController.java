package com.oconde.gateway.controller;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PostMapping;
import com.oconde.gateway.config.security.authentication.JwtAuthenticationProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import com.oconde.gateway.dto.AuthRequest;
import reactor.core.publisher.Mono;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final ReactiveAuthenticationManager authenticationManager;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    public AuthController(ReactiveAuthenticationManager authenticationManager, JwtAuthenticationProvider jwtAuthenticationProvider) {
        this.authenticationManager = authenticationManager;
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<Map<String, String>>> login(@RequestBody Mono<AuthRequest> requestMono) {

        return requestMono
                .flatMap(request -> authenticationManager
                        .authenticate(new UsernamePasswordAuthenticationToken(request.username(), request.password()))
                )
                .map(auth -> {
                    String token = jwtAuthenticationProvider.generateToken(auth.getName());
                    return ResponseEntity.ok(Map.of("token", token));
                })
                // Manejo reactivo de errores si credenciales son inválidas
                .onErrorResume(AuthenticationException.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build())
                );
    }
}