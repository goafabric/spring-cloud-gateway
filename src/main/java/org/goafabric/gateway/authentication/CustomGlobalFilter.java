package org.goafabric.gateway.authentication;


import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
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
                    .filter(ctx -> ctx.getAuthentication() != null)
                    .flatMap(ctx -> {
                        var authentication = (OAuth2AuthenticationToken) ctx.getAuthentication();
                        var tenantId = authentication.getAuthorizedClientRegistrationId();
                        if (tenantId == null) {
                            return Mono.error(new AccessDeniedException("Invalid token. Tenant is not present in token."));
                        }

                        var request = exchange.getRequest().mutate()
                                .header("X-TenantId", tenantId)
                                .header("X-Auth-Request-Preferred-Username", authentication.getName())
                                .build();

                        return chain.filter(exchange.mutate().request(request).build());
                    })
                    .switchIfEmpty(chain.filter(exchange));

        };

    }
}