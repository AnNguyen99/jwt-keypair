package com.rikkei.jwt.security.jwt;

import com.rikkei.jwt.management.SecurityMetersService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import tech.jhipster.config.JHipsterProperties;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider {

    private final Logger log = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    private static final String INVALID_JWT_TOKEN = "Invalid JWT token.";

    private final JwtParser jwtParser;

    private final long tokenValidityInMilliseconds;

    private final long tokenValidityInMillisecondsForRememberMe;

    private final SecurityMetersService securityMetersService;

    private final PrivateKey privateKey;

    private final PublicKey publicKey;

    public TokenProvider(JHipsterProperties jHipsterProperties, SecurityMetersService securityMetersService) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final String privateKeyBase64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDZkj4YTQ0VU7NUSuaj4yOs3te08Bjz3wF+hB1j2hfOXHfVY0yG5c3YxWzGAESAbh7WlL97lS+U4qJVp0S4ex85jQnLOv75C4XAE+UPM3wLH67lwg2wYfUQwVnAaPyrAyzUe5DBlxhy7Z+unD4zS0G5+7i+45Q20x0L6A1opj9xaTLbr36Wh/7UX9HM+H93wdB/FMu4l8nqN41WS8pO/hL/4+aNMwzEUbtHwCFxVFqlwfnJiEGoyKma/zi+QMI7pv5S6E+BqLR8rgTYZ1OU5MIo/NofYmq/HY0iHXA0LxpiQNTYij3erAW52NgA+h8/5YLOuvERb3T3725uNL+tmQnlAgMBAAECggEAC4GqewqIKJqWn1yeuggnONtIOS+BglRG9fPywfckzysgw05PG8tHibFXQVl+RfSM+PhA8D5Bl/Qsda80+TS5wAdvfyoNlgo/9pqWwKkOZGA2lbwfkTZ9CXfQUVa8FidC1bH7Q+HDz0A187wbpgbS4Q0pBh9vFT8xCBIrs18nd83pf5r16kP3o4jISnGzsfMNgrw+0bu+EbDy8vKMw9meGIZiCLDX7pfYi/kzdd8VbQ0HjAo8c0U4XkyCq4TGxKL8GoijV8yG6GQrWRP8oiHc1nKvsKBp895s1PiBSJP+XYBC1XD5xYKrBTEM0vcNINF0YsEqG8CIuz5uupPwk7CfeQKBgQD24bemsRbofKGk4O8gtdJikXRUUThFCGBlYFLmpY5v2IgnfZdQKAx4k83XRy1eVI/mRmL0fyBToBYJWZAHXSUQrSfoemYg5ZVamCQfy5q7lTTfLBeXnhOD6F+l5QhbKUhpDH9FqeSwrn62UbBun4LSU5lRypD+u+rIOysn7SZc6wKBgQDhm2SZ6SS5BSLJRIWXzbKbvL/Q7JNiNautza51lJRGq4h25NotNxkn1MJSgWpAHGz4/cUZWWVMHkyHlJe+dTNvFhy8rJGz34wzr9c9YRwDTfHGaZvhb+ToCHOdnhZtkf/uG9N8FbmOEy0TWs0BvB0r9cXS6VB3br+El5X9aTRAbwKBgQCj4sjYJfywDnP7kLoM+8YSWr5fbp8s7FeZVG0T4VkBlDsmA/AbbMqCjJN7Uiuiz/3KfnUYGv/po36dbE/5I3MEc/3nDMGZGu6fehmY5b7swSqc75cltfD8gphj9vsqEOiZm4stQo+mXd+NxgKaHNdqKcbAjfjcsQA1NVn7oijySwKBgQCqyGJIbIgjE3M43wkuWEVrxV+DPYN4Zd6XTEtTsOzp7nH4ZteOQNZnI5UStesDq0EG37vzq4uWKp2OSPrx73DHF/sbDJujiYdtnSAX08pL6hYrN8kLyBOFXth+qayat1oBGslmdl+n4HZP332vYYLHw15EgeAq+Qg7zDB7y8cFOwKBgCVEjCCkV390Y5WRxdHyXMG/zCjXA051M8SS9Pg3lregYYgsgknppw+v54pjE31oHB7kkAUKfEgB1hla38d4+LW3cWK1uMLoKtCGBVf6kplgsqlGKuG+t28jeUu+vJVwI9jzRDm49nFcmSQrz+cMavjcT8UOewwa/k6RFNItxA5a";
        final String publicKeyBase64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ZI+GE0NFVOzVErmo+MjrN7XtPAY898BfoQdY9oXzlx31WNMhuXN2MVsxgBEgG4e1pS/e5UvlOKiVadEuHsfOY0Jyzr++QuFwBPlDzN8Cx+u5cINsGH1EMFZwGj8qwMs1HuQwZcYcu2frpw+M0tBufu4vuOUNtMdC+gNaKY/cWky269+lof+1F/RzPh/d8HQfxTLuJfJ6jeNVkvKTv4S/+PmjTMMxFG7R8AhcVRapcH5yYhBqMipmv84vkDCO6b+UuhPgai0fK4E2GdTlOTCKPzaH2Jqvx2NIh1wNC8aYkDU2Io93qwFudjYAPofP+WCzrrxEW909+9ubjS/rZkJ5QIDAQAB";
        final byte[] privateKeyRaw = Base64.getDecoder().decode(privateKeyBase64);
        final byte[] publicKeyRaw = Base64.getDecoder().decode(publicKeyBase64);
        final PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyRaw);
        final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyRaw);

        this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
        this.publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

        jwtParser = Jwts.parserBuilder().setSigningKey(publicKey).build();
        this.tokenValidityInMilliseconds = 1000 * jHipsterProperties.getSecurity().getAuthentication().getJwt().getTokenValidityInSeconds();
        this.tokenValidityInMillisecondsForRememberMe =
            1000 * jHipsterProperties.getSecurity().getAuthentication().getJwt().getTokenValidityInSecondsForRememberMe();

        this.securityMetersService = securityMetersService;
    }

    public String createToken(Authentication authentication, boolean rememberMe) {
        String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date validity;
        if (rememberMe) {
            validity = new Date(now + this.tokenValidityInMillisecondsForRememberMe);
        } else {
            validity = new Date(now + this.tokenValidityInMilliseconds);
        }

        return Jwts
            .builder()
            .setSubject(authentication.getName())
            .claim(AUTHORITIES_KEY, authorities)
            .signWith(privateKey, SignatureAlgorithm.RS256)
            .setExpiration(validity)
            .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = jwtParser.parseClaimsJws(token).getBody();

        Collection<? extends GrantedAuthority> authorities = Arrays
            .stream(claims.get(AUTHORITIES_KEY).toString().split(","))
            .filter(auth -> !auth.trim().isEmpty())
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public boolean validateToken(String authToken) {
        try {
            jwtParser.parseClaimsJws(authToken);

            return true;
        } catch (ExpiredJwtException e) {
            this.securityMetersService.trackTokenExpired();

            log.trace(INVALID_JWT_TOKEN, e);
        } catch (UnsupportedJwtException e) {
            this.securityMetersService.trackTokenUnsupported();

            log.trace(INVALID_JWT_TOKEN, e);
        } catch (MalformedJwtException e) {
            this.securityMetersService.trackTokenMalformed();

            log.trace(INVALID_JWT_TOKEN, e);
        } catch (SignatureException e) {
            this.securityMetersService.trackTokenInvalidSignature();

            log.trace(INVALID_JWT_TOKEN, e);
        } catch (IllegalArgumentException e) { // TODO: should we let it bubble (no catch), to avoid defensive programming and follow the fail-fast principle?
            log.error("Token validation error {}", e.getMessage());
        }

        return false;
    }
}
