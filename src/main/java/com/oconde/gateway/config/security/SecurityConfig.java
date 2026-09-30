package com.oconde.gateway.config.security;

import com.oconde.gateway.config.security.authentication.JwtReactiveAuthenticationManager;
import com.oconde.gateway.config.security.authentication.LdapReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Bean;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    @Primary
    public ReactiveAuthenticationManager delegatingAuthenticationManager(LdapReactiveAuthenticationManager ldapManager,
                                                                         JwtReactiveAuthenticationManager jwtManager) {
        // Este manager evaluará la lista en orden.
        // Si uno devuelve Mono.empty(), pasa al siguiente.
        return new DelegatingReactiveAuthenticationManager(ldapManager, jwtManager);
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            ReactiveAuthenticationManager authenticationManager) {

        // 1. Usamos el converter nativo de Spring (extrae el header "Bearer ...")
        ServerBearerTokenAuthenticationConverter bearerConverter = new ServerBearerTokenAuthenticationConverter();

        // 2. Configuramos el filtro con nuestro Manager unificado y el Converter de Spring
        AuthenticationWebFilter jwtFilter = new AuthenticationWebFilter(authenticationManager);
        jwtFilter.setServerAuthenticationConverter(bearerConverter);

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/auth/login", "/actuator/**").permitAll()// Login y Actuator públicos
                        .anyExchange().authenticated()                             // El resto exige JWT válido
                )
                // Añadimos nuestro filtro JWT antes del filtro de autorización
                .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
}