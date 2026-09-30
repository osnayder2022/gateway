package com.oconde.gateway.middleware;

import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.core.Ordered;
import reactor.core.publisher.Mono;

@Component
public class JwtToHeaderGlobalFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated) // Aseguramos que esté autenticado
                .flatMap(authentication -> {
                    // Obtenemos el loginName. Dependiendo de cómo lo setees en tu JwtAuthenticationManager,
                    // normalmente se guarda en el getName() o en el getPrincipal()
                    String loginName = authentication.getName();

                    if (loginName != null && !loginName.isEmpty()) {
                        // Mutamos la petición inyectando el header
                        ServerWebExchange mutatedExchange = exchange.mutate()
                                .request(req -> req.header("X-User-Id", loginName))
                                .build();
                        return chain.filter(mutatedExchange);
                    }

                    return chain.filter(exchange);
                })
                // Si el contexto está vacío (endpoints públicos permitidos en el SecurityWebFilterChain)
                .switchIfEmpty(chain.filter(exchange));
    }

    @Override
    public int getOrder() {
        return -1; // Prioridad alta para que se ejecute antes del enrutamiento final
    }
}
