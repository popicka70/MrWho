package com.mrwho.demo

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class WellKnownController {

    // Chrome DevTools sometimes probes this path and, if it hits auth, it can become the "saved request".
    // Returning 204 avoids a confusing post-login navigation to a 404 error page.
    @GetMapping("/.well-known/appspecific/com.chrome.devtools.json")
    fun chromeDevtools(): ResponseEntity<Void> = ResponseEntity.noContent().build()
}
