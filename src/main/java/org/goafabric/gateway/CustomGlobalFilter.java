package org.goafabric.gateway;


import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.file.AccessDeniedException;

@Component
public class CustomGlobalFilter {

    @Bean
    public GlobalFilter globalFilter() {
        return (exchange, chain) -> {
            return ReactiveSecurityContextHolder.getContext()
                    .filter(c -> c.getAuthentication() != null)
                    .flatMap(c -> {
                        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) c.getAuthentication();

                        String tokenTenant = token.getAuthorizedClientRegistrationId();
                        if (tokenTenant == null) {
                            return Mono.error(
                                    new AccessDeniedException("Invalid token. Tenant is not present in token.")
                            );
                        }

                        ServerHttpRequest request = exchange.getRequest().mutate()
                                .header("X-TenantId", tokenTenant).build();

                        return chain.filter(exchange.mutate().request(request).build());
                    })
                    .switchIfEmpty(chain.filter(exchange));

        };


    }
}