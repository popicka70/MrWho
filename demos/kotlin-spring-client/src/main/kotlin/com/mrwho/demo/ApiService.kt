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
        val url = "${demo.apiBaseUrl.trimEnd('/')}/identity"
        val json = webClient.get()
            .uri(url)
            .header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
            .exchangeToMono { resp ->
                when {
                    resp.statusCode().is2xxSuccessful -> resp.bodyToMono(String::class.java)
                    resp.statusCode().is3xxRedirection -> {
                        val location = resp.headers().asHttpHeaders().getFirst(HttpHeaders.LOCATION)
                        resp.bodyToMono(String::class.java).defaultIfEmpty("")
                            .map { body ->
                                throw IllegalStateException(
                                    "Identity endpoint redirect (${resp.rawStatusCode()}) to ${location ?: "(no Location)"}. Body: $body"
                                )
                            }
                    }
                    else -> resp.bodyToMono(String::class.java).defaultIfEmpty("")
                        .map { body ->
                            throw IllegalStateException("Identity endpoint error (${resp.rawStatusCode()}): $body")
                        }
                }
            }
            .block()
            ?.takeIf { it.isNotBlank() }
            ?: throw IllegalStateException("Empty identity response")

        val parsed = objectMapper.readValue(json, IdentityResponse::class.java)
        return parsed to json
    }
}
