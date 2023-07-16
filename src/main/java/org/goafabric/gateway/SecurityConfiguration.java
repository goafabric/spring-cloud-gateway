package org.goafabric.gateway;

import io.micrometer.observation.ObservationPredicate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Configuration
public class SecurityConfiguration {
    @Value("${security.authentication.enabled}") private Boolean isAuthenticationEnabled;

    @Value("${spring.security.oauth2.base-uri}") private String baseUri;
    @Value("${spring.security.oauth2.authorization-uri}") private String authorizationUri;
    @Value("${spring.security.oauth2.logout-uri:}") private String logoutUri;
    @Value("${spring.security.oauth2.prefix:}") private String prefix;


    @Value("${spring.security.oauth2.client-id}") private String clientId;
    @Value("${spring.security.oauth2.client-secret}") private String clientSecret;
    @Value("${spring.security.oauth2.user-name-attribute:}") private String userNameAttribute;

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http, TenantClientRegistrationRepository clientRegistrationRepository) throws Exception {
        if (isAuthenticationEnabled) {
            var loginUrl = "/oauth2/login.html";
            //var logoutHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
            //logoutHandler.setPostLogoutRedirectUri("{baseUrl}/login.html"); //yeah that's right, we need baseUrl here, because it's an absolute url and below its a relative url - WTF
            http
                    .authorizeExchange(authorize -> authorize
                            .pathMatchers("/" ,"/actuator/**", loginUrl).permitAll()
                            .anyExchange().authenticated())
                    .oauth2Login(oauth2 -> oauth2
                            .clientRegistrationRepository(clientRegistrationRepository))
                    //.logout(l -> l.logoutSuccessHandler(logoutHandler))
                    .csrf(c -> c.disable())
                    .exceptionHandling(exception ->
                            exception.authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint(loginUrl)));
        } else {
            http.authorizeExchange(auth -> auth.anyExchange().permitAll()).csrf(csrf -> csrf.disable());
        }
        return http.build();
    }


    @Component
    class TenantClientRegistrationRepository implements ReactiveClientRegistrationRepository {

        private static final Map<String,Mono<ClientRegistration>> clientRegistrations = new ConcurrentHashMap<>();

        @Override
        public Mono<ClientRegistration> findByRegistrationId(String registrationId) {
            return clientRegistrations.computeIfAbsent(registrationId, this::buildClientRegistration);
        }

        private Mono<ClientRegistration> buildClientRegistration(String tenantId) {
            var providerDetails = new HashMap<String, Object>();
            providerDetails.put("end_session_endpoint", !logoutUri.equals("") ? logoutUri.replaceAll("\\{tenantId}", tenantId) : null);

            return Mono.just(ClientRegistration.withRegistrationId(tenantId)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .scope("openid")
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .userNameAttributeName(userNameAttribute)
                    .authorizationUri(authorizationUri.replaceAll("\\{tenantId}", tenantId))
                    .tokenUri(baseUri.replaceAll("\\{tenantId}", tenantId) + "/token")
                    .userInfoUri(baseUri.replaceAll("\\{tenantId}", tenantId) + "/userinfo")
                    .jwkSetUri(baseUri.replaceAll("\\{tenantId}", tenantId) + "/certs")
                    .providerConfigurationMetadata(providerDetails)
                    .build());
        }
    }

    @Bean
    ObservationPredicate disableHttpServerObservationsFromName() {
        return (name, context) -> !name.startsWith("spring.security.");
    }

}

