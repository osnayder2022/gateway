package com.oconde.gateway.config.security;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayRoutingConfig {

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("products-service", r -> r
                        // Definimos explícitamente ambas rutas sin riesgo de errores de sintaxis
                        .path("/api/products", "/api/products/**")
                        .uri("http://localhost:8086")
                )
                .build();
    }
}