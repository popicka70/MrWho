package com.mrwho.demo

data class IdentityResponse(
    val type: String? = null,
    val message: String? = null,
    val clientId: String? = null,
    val subject: String? = null,
    val audience: String? = null,
    val scopes: Any? = null,
    val issuedAt: String? = null,
    val expiresAt: String? = null
)

data class TokenComparisonResult(
    val obo: IdentityResponse? = null,
    val m2m: IdentityResponse? = null,
    val error: String? = null,
    val oboJson: String? = null,
    val m2mJson: String? = null
)
