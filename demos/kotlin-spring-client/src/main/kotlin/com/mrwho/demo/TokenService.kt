package com.mrwho.demo

import com.fasterxml.jackson.databind.JsonNode
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.stereotype.Service
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import java.util.Base64

@Service
class TokenService(
    private val authorizedClientService: OAuth2AuthorizedClientService,
    private val clientRegistrationRepository: ClientRegistrationRepository,
    private val webClient: WebClient,
    private val demo: DemoProperties
) {

    private fun basicAuthorizationHeaderValue(): String {
        val raw = "${clientId()}:${clientSecret()}"
        val encoded = Base64.getEncoder().encodeToString(raw.toByteArray(Charsets.US_ASCII))
        return "Basic $encoded"
    }

    fun getUserAccessToken(principalName: String): String {
        val client = authorizedClientService.loadAuthorizedClient<OAuth2AuthorizedClient>("mrwho", principalName)
            ?: throw IllegalStateException("No authorized client found. Please sign in again.")

        val accessToken = client.accessToken
            ?: throw IllegalStateException("No access token available.")

        return accessToken.tokenValue
    }

    fun tokenEndpoint(): String {
        val registration = clientRegistrationRepository.findByRegistrationId("mrwho")
            ?: throw IllegalStateException("OAuth2 client registration 'mrwho' not found.")
        return registration.providerDetails.tokenUri
    }

    fun clientId(): String {
        val registration = clientRegistrationRepository.findByRegistrationId("mrwho")
            ?: throw IllegalStateException("OAuth2 client registration 'mrwho' not found.")
        return registration.clientId
    }

    fun clientSecret(): String {
        val registration = clientRegistrationRepository.findByRegistrationId("mrwho")
            ?: throw IllegalStateException("OAuth2 client registration 'mrwho' not found.")
        return registration.clientSecret
    }

    fun acquireClientCredentialsToken(): String {
        val form = LinkedMultiValueMap<String, String>().apply {
            add("grant_type", "client_credentials")
            add("client_id", clientId())
            add("audience", demo.apiAudience)
        }

        val json = webClient.post()
            .uri(tokenEndpoint())
            .header(HttpHeaders.AUTHORIZATION, basicAuthorizationHeaderValue())
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData(form))
            .exchangeToMono { resp ->
                if (resp.statusCode().is2xxSuccessful) {
                    resp.bodyToMono(JsonNode::class.java)
                } else {
                    resp.bodyToMono(String::class.java).defaultIfEmpty("")
                        .map { body ->
                            throw IllegalStateException("Token endpoint error (${resp.rawStatusCode()}): $body")
                        }
                }
            }
            .block()
            ?: throw IllegalStateException("Empty token response")

        val token = json.get("access_token")?.asText()
        if (token.isNullOrBlank()) throw IllegalStateException("No access_token in token response")
        return token
    }

    fun exchangeOnBehalfOf(userAccessToken: String): String {
        val form = LinkedMultiValueMap<String, String>().apply {
            add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
            add("client_id", clientId())
            add("subject_token", userAccessToken)
            add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
            add("audience", demo.apiAudience)
            add("scope", "openid profile email api.read")
            add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
        }

        val json = webClient.post()
            .uri(tokenEndpoint())
            .header(HttpHeaders.AUTHORIZATION, basicAuthorizationHeaderValue())
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData(form))
            .exchangeToMono { resp ->
                if (resp.statusCode().is2xxSuccessful) {
                    resp.bodyToMono(JsonNode::class.java)
                } else {
                    resp.bodyToMono(String::class.java).defaultIfEmpty("")
                        .map { body ->
                            throw IllegalStateException("Token exchange error (${resp.rawStatusCode()}): $body")
                        }
                }
            }
            .block()
            ?: throw IllegalStateException("Empty token exchange response")

        val token = json.get("access_token")?.asText()
        if (token.isNullOrBlank()) throw IllegalStateException("No access_token in token exchange response")
        return token
    }
}
