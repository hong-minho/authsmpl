package com.example.authsmpl.service;

import com.example.authsmpl.config.AdfsProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Collection;

/**
 * JWT 유효성 검사 서비스.
 *
 * 검사 항목:
 * <ul>
 *   <li>Bearer 토큰 존재 여부</li>
 *   <li>kid 추출 → JWKS 공개키 조회</li>
 *   <li>RS256 서명 검증</li>
 *   <li>exp (만료 시간) 검증</li>
 *   <li>iss (발급자) 검증</li>
 *   <li>aud (대상) 검증</li>
 * </ul>
 */
@Service
public class JwtValidationService {

    private static final Logger log = LoggerFactory.getLogger(JwtValidationService.class);

    private final JwksService jwksService;
    private final AdfsProperties props;

    public JwtValidationService(JwksService jwksService, AdfsProperties props) {
        this.jwksService = jwksService;
        this.props = props;
    }

    /**
     * 토큰을 검증하고 Claims를 반환한다.
     *
     * @param token  Authorization 헤더에서 추출한 순수 토큰 문자열 (Bearer 제외)
     * @return 파싱된 Claims
     * @throws JwtAuthException 검증 실패 시
     */
    public Claims validate(String token) {
        if (token == null || token.isBlank()) {
            throw new JwtAuthException("Missing token");
        }

        // ── 1. 헤더에서 kid 추출 (서명 검증 전 헤더만 파싱) ─────────────────
        String kid = extractKid(token);

        if (kid != null) {
            // ── 2a. kid 있음 → 해당 공개키로 검증 ───────────────────────────
            PublicKey publicKey = jwksService.getPublicKey(kid);
            if (publicKey == null) {
                throw new JwtAuthException("Unknown kid: " + kid);
            }
            return validateWithKey(token, publicKey);
        } else {
            // ── 2b. kid 없음 (ADFS 등) → 캐시된 키 전체 순회 검증 ───────────
            log.debug("JWT header has no 'kid', trying all cached keys");
            return validateWithAllKeys(token);
        }
    }

    /**
     * 단일 공개키로 서명 + 클레임을 검증한다.
     */
    private Claims validateWithKey(String token, PublicKey publicKey) {
        try {
            JwtParser parser = Jwts.parser()
                    .verifyWith(publicKey)
                    .requireIssuer(props.getIssuer())
                    .requireAudience(props.getAudience())
                    .build();

            Claims claims = parser.parseSignedClaims(token).getPayload();
            log.debug("JWT validated. sub={}, exp={}", claims.getSubject(), claims.getExpiration());
            return claims;

        } catch (ExpiredJwtException e) {
            throw new JwtAuthException("Token expired: " + e.getMessage());
        } catch (SignatureException e) {
            throw new JwtAuthException("Invalid token signature");
        } catch (MissingClaimException | IncorrectClaimException e) {
            throw new JwtAuthException("Token claim validation failed: " + e.getMessage());
        } catch (JwtException e) {
            throw new JwtAuthException("Token validation error: " + e.getMessage());
        }
    }

    /**
     * kid가 없을 때 캐시된 모든 공개키를 순회하며 검증을 시도한다.
     * 하나라도 성공하면 해당 Claims를 반환하고, 모두 실패하면 예외를 던진다.
     */
    private Claims validateWithAllKeys(String token) {
        Collection<PublicKey> allKeys = jwksService.getAllPublicKeys();
        if (allKeys.isEmpty()) {
            throw new JwtAuthException("No public keys available in JWKS cache");
        }

        // 만료·클레임 오류는 키 문제가 아니므로 첫 번째 발생 시 즉시 전파
        for (PublicKey publicKey : allKeys) {
            try {
                JwtParser parser = Jwts.parser()
                        .verifyWith(publicKey)
                        .requireIssuer(props.getIssuer())
                        .requireAudience(props.getAudience())
                        .build();

                Claims claims = parser.parseSignedClaims(token).getPayload();
                log.debug("JWT validated (no-kid, key found by trial). sub={}, exp={}",
                        claims.getSubject(), claims.getExpiration());
                return claims;

            } catch (ExpiredJwtException e) {
                throw new JwtAuthException("Token expired: " + e.getMessage());
            } catch (MissingClaimException | IncorrectClaimException e) {
                throw new JwtAuthException("Token claim validation failed: " + e.getMessage());
            } catch (JwtException e) {
                // 이 키로는 서명 불일치 → 다음 키 시도
                log.debug("Key mismatch (no-kid trial): {}", e.getMessage());
            }
        }

        throw new JwtAuthException("No matching key found for token (tried " + allKeys.size() + " key(s))");
    }

    /**
     * 서명 검증 없이 JWT 헤더만 파싱하여 kid를 추출한다.
     */
    private String extractKid(String token) {
        try {
            // JJWT 0.12.x: unsecured parser로 헤더만 읽기
            // parseUnsecuredHeader()는 서명된 JWT에서 헤더만 추출할 때 사용
            int firstDot = token.indexOf('.');
            if (firstDot < 0) return null;

            String headerB64 = token.substring(0, firstDot);
            // Base64Url 패딩 보정
            int pad = headerB64.length() % 4;
            if (pad != 0) headerB64 += "=".repeat(4 - pad);

            byte[] decoded = java.util.Base64.getUrlDecoder().decode(headerB64);
            com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode headerNode = om.readTree(decoded);
            com.fasterxml.jackson.databind.JsonNode kidNode = headerNode.get("kid");
            return (kidNode != null) ? kidNode.asText() : null;

        } catch (Exception e) {
            log.warn("Failed to extract kid from JWT header: {}", e.getMessage());
            return null;
        }
    }

    // ── 검증 실패 예외 ─────────────────────────────────────────────────────────

    public static class JwtAuthException extends RuntimeException {
        public JwtAuthException(String message) {
            super(message);
        }
    }
}
