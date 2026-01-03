package com.mrwho.demo

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping

@Controller
class PagesController(
    private val tokenService: TokenService,
    private val apiService: ApiService,
    private val objectMapper: ObjectMapper
) {

    @GetMapping("/")
    fun home(model: Model, authentication: Authentication?): String {
        model.addAttribute("isAuthenticated", authentication != null)
        model.addAttribute("principalName", authentication?.name)
        return "index"
    }

    @GetMapping("/token-comparison")
    fun tokenComparison(model: Model): String {
        model.addAttribute("result", TokenComparisonResult())
        return "token-comparison"
    }

    @PostMapping("/token-comparison/call-obo")
    fun callObo(model: Model, authentication: Authentication): String {
        return try {
            val userToken = tokenService.getUserAccessToken(authentication.name)
            val exchanged = tokenService.exchangeOnBehalfOf(userToken)
            val (resp, json) = apiService.callIdentity(exchanged)
            model.addAttribute("result", TokenComparisonResult(obo = resp, oboJson = pretty(json)))
            "token-comparison"
        } catch (ex: Exception) {
            model.addAttribute("result", TokenComparisonResult(error = "OBO Error: ${ex.message}"))
            "token-comparison"
        }
    }

    @PostMapping("/token-comparison/call-m2m")
    fun callM2m(model: Model): String {
        return try {
            val token = tokenService.acquireClientCredentialsToken()
            val (resp, json) = apiService.callIdentity(token)
            model.addAttribute("result", TokenComparisonResult(m2m = resp, m2mJson = pretty(json)))
            "token-comparison"
        } catch (ex: Exception) {
            model.addAttribute("result", TokenComparisonResult(error = "M2M Error: ${ex.message}"))
            "token-comparison"
        }
    }

    @PostMapping("/token-comparison/call-both")
    fun callBoth(model: Model, authentication: Authentication): String {
        return try {
            val userToken = tokenService.getUserAccessToken(authentication.name)
            val oboToken = tokenService.exchangeOnBehalfOf(userToken)
            val m2mToken = tokenService.acquireClientCredentialsToken()

            val (oboResp, oboJson) = apiService.callIdentity(oboToken)
            val (m2mResp, m2mJson) = apiService.callIdentity(m2mToken)

            model.addAttribute(
                "result",
                TokenComparisonResult(
                    obo = oboResp,
                    m2m = m2mResp,
                    oboJson = pretty(oboJson),
                    m2mJson = pretty(m2mJson)
                )
            )
            "token-comparison"
        } catch (ex: Exception) {
            model.addAttribute("result", TokenComparisonResult(error = "Error: ${ex.message}"))
            "token-comparison"
        }
    }

    private fun pretty(rawJson: String): String {
        val node = objectMapper.readTree(rawJson)
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(node)
    }
}
