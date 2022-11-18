package com.klimber.opaquetoken.oauth;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

/**
 * Simple and potentially flawed implementation of a user token repository.
 *
 * <p>It's responsible for storing token-user relations to enable token introspection, note that as an in-memory token
 * store this is not suitable for horizontal scaling. A third party resource server is more recommended.</p>
 */
@Repository
public class TokenRepository {

    private static final Map<String, ExpiringUserCredential> TOKENS = new ConcurrentHashMap<>();
    private static final Map<String, String> USER_TOKENS = new ConcurrentHashMap<>();
    public static final int TOKEN_VALID_MINUTES = 60;

    public Optional<UserDetails> get(String token) {
        return Optional.ofNullable(TOKENS.get(token))
                       .filter(credential -> credential.expiresAt().isAfter(Instant.now()))
                       .map(ExpiringUserCredential::user);
    }

    public void add(String token, UserDetails user) {
        removeExpired();
        removePreviousTokenForUser(user);
        USER_TOKENS.put(user.getUsername(), token);
        TOKENS.put(token, new ExpiringUserCredential(user, Instant.now().plus(TOKEN_VALID_MINUTES,
                                                                              ChronoUnit.MINUTES)));
    }

    public void remove(String token) {
        ExpiringUserCredential removed = TOKENS.remove(token);
        if (removed != null) {
            USER_TOKENS.remove(removed.user().getUsername());
        }
    }

    private static void removeExpired() {
        TOKENS.entrySet().removeIf(entry -> {
            if (entry.getValue().expiresAt().isAfter(Instant.now())) {
                return false;
            }
            USER_TOKENS.remove(entry.getValue().user().getUsername());
            return true;
        });
    }

    private void removePreviousTokenForUser(UserDetails user) {
        String currentToken = USER_TOKENS.remove(user.getUsername());
        if (currentToken != null) {
            remove(currentToken);
        }
    }
}
