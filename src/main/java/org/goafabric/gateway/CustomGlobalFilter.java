package org.goafabric.gateway;


import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class CustomGlobalFilter {

    @Bean
    public GlobalFilter globalFilter() {
        return (exchange, chain) -> {
            Mono<Authentication> auth = ReactiveSecurityContextHolder.getContext().map(ctx -> ctx.getAuthentication());
            auth.subscribe(a ->
                exchange.getRequest().mutate()
                        .header("X-TenantId", ((OAuth2AuthenticationToken)a).getAuthorizedClientRegistrationId()).build());
            return chain.filter(exchange);
        };
    }
}