package com.mrwho.demo

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import io.ktor.client.*
import io.ktor.client.call.body
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.*
import kotlinx.coroutines.runBlocking

// Disambiguate server/client ContentNegotiation plugins
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation

fun main(args: Array<String>) = EngineMain.main(args)

data class UserSession(
    val idToken: String? = null,
    val accessToken: String? = null,
    val refreshToken: String? = null,
    val state: String? = null
)

@Suppress("unused")
fun Application.module() {
    install(ServerContentNegotiation) {
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
        install(ClientContentNegotiation) { jackson() }
    }

    val authority = environment.config.propertyOrNull("mrwho.authority")?.getString()?.trimEnd('/')
        ?: "https://mrwho-production.up.railway.app"
    val clientId = environment.config.propertyOrNull("mrwho.clientId")?.getString() ?: "demo.web"
    val clientSecret = environment.config.propertyOrNull("mrwho.clientSecret")?.getString() ?: "Demo1Secret2024!"
    val redirectUrl = environment.config.propertyOrNull("mrwho.redirectUrl")?.getString() ?: "http://localhost:8085/callback"
    val postLogoutRedirectUrl = environment.config.propertyOrNull("mrwho.postLogoutRedirectUrl")?.getString() ?: "http://localhost:8085/"
    val scopes = environment.config.propertyOrNull("mrwho.scopes")?.getList()
        ?: listOf("openid", "profile", "email", "offline_access")

    val wellKnown = "${authority}/.well-known/openid-configuration"

    @JsonIgnoreProperties(ignoreUnknown = true)
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

    data class TokenResponse(
        val access_token: String? = null,
        val id_token: String? = null,
        val refresh_token: String? = null,
        val token_type: String? = null,
        val expires_in: Long? = null,
        val scope: String? = null
    )

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

        get("/login") {
            val state = generateNonce()
            val current = call.sessions.get<UserSession>() ?: UserSession()
            call.sessions.set(current.copy(state = state))

            val d = runBlocking { discover() }
            val url = URLBuilder(d.authorization_endpoint).apply {
                parameters.append("response_type", "code")
                parameters.append("client_id", clientId)
                parameters.append("redirect_uri", redirectUrl)
                parameters.append("scope", scopes.joinToString(" "))
                parameters.append("state", state)
            }.buildString()
            call.respondRedirect(url)
        }

        get("/callback") {
            val error = call.request.queryParameters["error"]
            if (error != null) {
                call.respond(HttpStatusCode.BadRequest, "OAuth error: $error")
                return@get
            }
            val code = call.request.queryParameters["code"]
            val state = call.request.queryParameters["state"]
            if (code.isNullOrBlank() || state.isNullOrBlank()) {
                call.respond(HttpStatusCode.BadRequest, "Missing code/state")
                return@get
            }
            val session = call.sessions.get<UserSession>()
            if (session?.state == null || session.state != state) {
                call.respond(HttpStatusCode.BadRequest, "Invalid state")
                return@get
            }

            val d = runBlocking { discover() }
            val tokenResp: TokenResponse = httpClient.submitForm(
                url = d.token_endpoint,
                formParameters = Parameters.build {
                    append("grant_type", "authorization_code")
                    append("code", code)
                    append("redirect_uri", redirectUrl)
                    append("client_id", clientId)
                    append("client_secret", clientSecret)
                }
            ) { method = HttpMethod.Post }.body()

            val newSession = UserSession(
                idToken = tokenResp.id_token,
                accessToken = tokenResp.access_token,
                refreshToken = tokenResp.refresh_token,
                state = null
            )
            call.sessions.set(newSession)
            call.respondRedirect("/")
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
