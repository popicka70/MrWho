package com.mrwho.demo

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers("/health", "/actuator/health", "/", "/css/**").permitAll()
                    .requestMatchers("/token-comparison").authenticated()
                    .requestMatchers("/token-comparison/**").authenticated()
                    .anyRequest().authenticated()
            }
            .oauth2Login(Customizer.withDefaults())
            .logout { logout ->
                logout.logoutSuccessUrl("/")
            }

        return http.build()
    }
}
