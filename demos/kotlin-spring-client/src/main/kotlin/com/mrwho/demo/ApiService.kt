package com.mrwho.demo

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.HttpHeaders
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient

@Service
class ApiService(
    private val webClient: WebClient,
    private val demo: DemoProperties,
    private val objectMapper: ObjectMapper
) {

    fun callIdentity(accessToken: String): Pair<IdentityResponse, String> {
        val json = webClient.get()
            .uri("${demo.apiBaseUrl.trimEnd('/')}/identity")
            .header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
            .retrieve()
            .bodyToMono(String::class.java)
            .block()
            ?: throw IllegalStateException("Empty identity response")

        val parsed = objectMapper.readValue(json, IdentityResponse::class.java)
        return parsed to json
    }
}
