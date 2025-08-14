package com.mrwho.demo

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.SerializationFeature
import io.ktor.client.*
import io.ktor.client.call.body
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.oauth.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.*
import kotlinx.coroutines.runBlocking

fun main(args: Array<String>) = EngineMain.main(args)

data class UserSession(val idToken: String? = null, val accessToken: String? = null, val refreshToken: String? = null)

@Suppress("unused")
fun Application.module() {
    install(ContentNegotiation) {
        jackson {
            enable(SerializationFeature.INDENT_OUTPUT)
            disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        }
    }

    install(Sessions) {
        cookie<UserSession>("mrwho.session", storage = SessionStorageMemory()) {
            cookie.path = "/"
            cookie.httpOnly = true
            cookie.extensions["SameSite"] = "Lax"
            cookie.secure = false // set true behind HTTPS
        }
    }

    val httpClient = HttpClient(Java) {
        install(ContentNegotiation) { jackson() }
    }

    val authority = environment.config.propertyOrNull("mrwho.authority")?.getString()?.trimEnd('/')
        ?: "https://localhost:7113"
    val clientId = environment.config.propertyOrNull("mrwho.clientId")?.getString() ?: "demo.web"
    val clientSecret = environment.config.propertyOrNull("mrwho.clientSecret")?.getString() ?: "dev-secret"
    val redirectUrl = environment.config.propertyOrNull("mrwho.redirectUrl")?.getString() ?: "http://localhost:8085/callback"
    val postLogoutRedirectUrl = environment.config.propertyOrNull("mrwho.postLogoutRedirectUrl")?.getString() ?: "http://localhost:8085/"
    val scopes = environment.config.propertyOrNull("mrwho.scopes")?.getList()
        ?: listOf("openid", "profile", "email", "offline_access")

    val wellKnown = "${authority}/.well-known/openid-configuration"

    data class DiscoveryDoc(
        val authorization_endpoint: String,
        val token_endpoint: String,
        val end_session_endpoint: String? = null,
        val jwks_uri: String? = null,
        val issuer: String? = null
    )

    suspend fun discover(): DiscoveryDoc {
        return httpClient.get(wellKnown).body()
    }

    install(Authentication) {
        oauth("mrwho-oauth") {
            urlProvider = { redirectUrl }
            client = httpClient
            providerLookup = {
                val d = runBlocking { discover() }
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "MrWho",
                    authorizeUrl = d.authorization_endpoint,
                    accessTokenUrl = d.token_endpoint,
                    requestMethod = HttpMethod.Post,
                    clientId = clientId,
                    clientSecret = clientSecret,
                    defaultScopes = scopes
                )
            }
        }
    }

    routing {
        get("/") {
            val session = call.sessions.get<UserSession>()
            if (session?.accessToken != null) {
                call.respondText(
                    """
                    <html>
                      <body>
                        <h2>MrWho Kotlin Ktor Demo</h2>
                        <p>You're signed in.</p>
                        <ul>
                            <li><a href="/me">View ID token</a></li>
                            <li><a href="/logout">Logout</a></li>
                        </ul>
                      </body>
                    </html>
                    """.trimIndent(),
                    ContentType.Text.Html
                )
            } else {
                call.respondText(
                    """
                    <html>
                      <body>
                        <h2>MrWho Kotlin Ktor Demo</h2>
                        <a href="/login">Sign in with MrWho</a>
                      </body>
                    </html>
                    """.trimIndent(),
                    ContentType.Text.Html
                )
            }
        }

        authenticate("mrwho-oauth") {
            get("/login") {
                // This just triggers the OAuth redirect
            }

            get("/callback") {
                val principal: OAuthAccessTokenResponse.OAuth2? = call.principal()
                if (principal == null) {
                    call.respond(HttpStatusCode.Unauthorized, "No principal returned")
                    return@get
                }
                val session = UserSession(
                    idToken = principal.extraParameters["id_token"],
                    accessToken = principal.accessToken,
                    refreshToken = principal.refreshToken
                )
                call.sessions.set(session)
                call.respondRedirect("/")
            }
        }

        get("/me") {
            val session = call.sessions.get<UserSession>()
            if (session?.idToken == null) {
                call.respondRedirect("/")
                return@get
            }
            call.respond(mapOf(
                "id_token" to session.idToken,
                "access_token" to session.accessToken,
                "has_refresh_token" to (session.refreshToken != null)
            ))
        }

        get("/logout") {
            val session = call.sessions.get<UserSession>()
            call.sessions.clear<UserSession>()
            val endSessionEndpoint = runBlocking { discover() }.end_session_endpoint
            if (endSessionEndpoint != null && session?.idToken != null) {
                val url = URLBuilder(endSessionEndpoint).apply {
                    parameters.append("id_token_hint", session.idToken)
                    parameters.append("post_logout_redirect_uri", postLogoutRedirectUrl)
                }.buildString()
                call.respondRedirect(url)
            } else {
                call.respondRedirect("/")
            }
        }
    }
}
