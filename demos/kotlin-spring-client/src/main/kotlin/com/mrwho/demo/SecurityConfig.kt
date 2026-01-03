package com.mrwho.demo

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.LogoutHandler

@Configuration
class SecurityConfig {

    @Bean
    fun securityFilterChain(
        http: HttpSecurity,
        clientRegistrationRepository: ClientRegistrationRepository,
        authorizedClientService: OAuth2AuthorizedClientService
    ): SecurityFilterChain {
        val pkceResolver = pkceAuthorizationRequestResolver(clientRegistrationRepository)

        http
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers("/health", "/actuator/health", "/", "/css/**", "/error", "/.well-known/**").permitAll()
                    .requestMatchers("/token-comparison").authenticated()
                    .requestMatchers("/token-comparison/**").authenticated()
                    .anyRequest().authenticated()
            }
            .oauth2Login { oauth2 ->
                oauth2
                    .authorizationEndpoint { endpoint ->
                        endpoint.authorizationRequestResolver(pkceResolver)
                    }
            }
            .logout { logout ->
                logout
                    .addLogoutHandler(clearAuthorizedClientOnLogout(authorizedClientService))
                    .invalidateHttpSession(true)
                    .clearAuthentication(true)
                    .deleteCookies("JSESSIONID")
                    .logoutSuccessUrl("/")
            }

        return http.build()
    }

    private fun clearAuthorizedClientOnLogout(authorizedClientService: OAuth2AuthorizedClientService): LogoutHandler {
        return LogoutHandler { _, _, authentication: Authentication? ->
            if (authentication != null) {
                authorizedClientService.removeAuthorizedClient("mrwho", authentication.name)
            }
        }
    }

    private fun pkceAuthorizationRequestResolver(
        clientRegistrationRepository: ClientRegistrationRepository
    ): OAuth2AuthorizationRequestResolver {
        val resolver = DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository,
            "/oauth2/authorization"
        )

        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce())
        return resolver
    }
}
