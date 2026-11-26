package com.myapp.auth.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Protected endpoint shown after login. Requires a valid access token. */
@RestController
public class HomeController {

    public record HomeResponse(String message, String userId) {
    }

    @GetMapping("/api/v1/home")
    public HomeResponse home(@AuthenticationPrincipal Jwt jwt) {
        return new HomeResponse("Hello World", jwt.getSubject());
    }
}
