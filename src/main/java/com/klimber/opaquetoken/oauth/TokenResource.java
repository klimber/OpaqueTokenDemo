package com.klimber.opaquetoken.oauth;

import java.security.SecureRandom;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Houses APIs for authentication and de-authentication
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/oauth")
public class TokenResource {
    public static final int LOGIN_DELAY_UPPER_BOUND_MILLIS = 1500;
    private final TokenRepository tokenRepository;
    private final DaoAuthenticationProvider daoAuthenticationProvider;
    private final SecureRandom random;

    /**
     * Given an username and password, tries to authenticate it with the UserDetailsService, creates a token for the
     * authenticated user, saves it to the token repository and returns the token.
     */
    @PostMapping("/token")
    public ResponseEntity<String> autenticate(
            @RequestBody UsernameAndPassword credentials) throws InterruptedException {
        synchronized (TokenResource.class) {
            // Very non-scalable way of preventing brute force with delay + synchronized
            Thread.sleep(random.nextInt(LOGIN_DELAY_UPPER_BOUND_MILLIS));
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(credentials.username(), credentials.password());
            Authentication authenticated = daoAuthenticationProvider.authenticate(authToken);
            String token = UUID.randomUUID().toString();
            tokenRepository.add(token, (UserDetails) authenticated.getPrincipal());
            return ResponseEntity.ok(token);
        }
    }

    /**
     * De-authenticates by removing token from token repository
     */
    @DeleteMapping("/token")
    public ResponseEntity<String> deAuthenticate(BearerTokenAuthentication principal) {
        tokenRepository.remove(principal.getToken().getTokenValue());
        return ResponseEntity.ok().build();
    }
}
