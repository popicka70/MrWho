package com.mrwho.demo

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.ExchangeStrategies
import org.springframework.web.reactive.function.client.WebClient

@ConfigurationProperties(prefix = "demo")
data class DemoProperties(
    val apiBaseUrl: String = "https://localhost:7200",
    val apiAudience: String = "obo-demo-api"
)

@Configuration
@EnableConfigurationProperties(DemoProperties::class)
class HttpClients {

    @Bean
    fun webClient(builder: WebClient.Builder): WebClient {
        val strategies = ExchangeStrategies.builder()
            .codecs { cfg -> cfg.defaultCodecs().maxInMemorySize(1024 * 1024) }
            .build()

        return builder
            .exchangeStrategies(strategies)
            .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .build()
    }
}
