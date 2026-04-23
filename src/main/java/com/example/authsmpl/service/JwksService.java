package com.example.authsmpl.service;

import com.example.authsmpl.config.AdfsProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ADFS JWKS 공개키 캐시 서비스.
 *
 * <pre>
 * 동작 방식:
 * 1. 최초 요청(또는 캐시 미존재) 시 JWKS 엔드포인트에서 공개키 목록 전체 로드
 * 2. kid → PublicKey 맵으로 메모리에 보관
 * 3. 토큰의 kid가 캐시에 없으면 쿨다운 시간이 지난 경우에 한해 재조회
 *    (ADFS 키 롤오버 대응 / 과도한 외부 호출 방지)
 * </pre>
 */
@Service
public class JwksService {

    private static final Logger log = LoggerFactory.getLogger(JwksService.class);

    private final AdfsProperties props;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient;

    /** kid → PublicKey 캐시 */
    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();

    /** 마지막 JWKS 갱신 시각 (쿨다운 계산용) */
    private volatile Instant lastRefreshedAt = Instant.EPOCH;

    public JwksService(AdfsProperties props) {
        this.props = props;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    /**
     * 캐시된 공개키 전체를 반환한다.
     * kid가 없는 토큰 검증 시 순회용으로 사용한다.
     *
     * @return 캐시에 있는 PublicKey 컬렉션 (비어 있을 수 있음)
     */
    public java.util.Collection<PublicKey> getAllPublicKeys() {
        if (keyCache.isEmpty()) {
            log.info("Key cache is empty, loading JWKS from {}", props.getJwksUri());
            refreshKeys();
        }
        return keyCache.values();
    }

    /**
     * kid에 해당하는 공개키를 반환한다.
     *
     * @param kid JWT 헤더의 kid 값
     * @return PublicKey, 없으면 null
     */
    public PublicKey getPublicKey(String kid) {
        if (kid == null || kid.isBlank()) {
            log.warn("JWT kid is null or blank");
            return null;
        }

        // 1. 캐시 히트
        PublicKey cached = keyCache.get(kid);
        if (cached != null) {
            return cached;
        }

        // 2. 캐시 미스 → 쿨다운 체크 후 재조회
        long cooldown = props.getJwksRefreshCooldownSeconds();
        boolean cooldownPassed = Duration.between(lastRefreshedAt, Instant.now()).getSeconds() >= cooldown;

        if (cooldownPassed) {
            log.info("kid '{}' not found in cache, refreshing JWKS from {}", kid, props.getJwksUri());
            refreshKeys();
        } else {
            log.warn("kid '{}' not in cache but cooldown not passed ({}s remaining). Rejecting token.",
                    kid,
                    cooldown - Duration.between(lastRefreshedAt, Instant.now()).getSeconds());
        }

        return keyCache.get(kid);
    }

    /**
     * 애플리케이션 기동 시 미리 공개키를 로드한다 (선택 호출).
     */
    public void preload() {
        log.info("Preloading JWKS keys from {}", props.getJwksUri());
        refreshKeys();
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private synchronized void refreshKeys() {
        // 동시 요청이 몰릴 때 중복 갱신 방지
        long cooldown = props.getJwksRefreshCooldownSeconds();
        if (Duration.between(lastRefreshedAt, Instant.now()).getSeconds() < cooldown) {
            log.debug("Skipping JWKS refresh: cooldown not elapsed");
            return;
        }

        try {
            String json = fetchJwks();
            Map<String, PublicKey> newKeys = parseJwks(json);

            if (newKeys.isEmpty()) {
                log.warn("JWKS response contained no usable RSA keys");
                return;
            }

            // 기존 캐시를 교체 (atomic swap)
            keyCache.clear();
            keyCache.putAll(newKeys);
            lastRefreshedAt = Instant.now();

            log.info("JWKS cache updated: {} key(s) loaded -> kids: {}", newKeys.size(), newKeys.keySet());

        } catch (Exception e) {
            log.error("Failed to refresh JWKS keys: {}", e.getMessage(), e);
        }
    }

    private String fetchJwks() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(props.getJwksUri()))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("JWKS fetch failed, HTTP " + response.statusCode());
        }
        return response.body();
    }

    /**
     * JWKS JSON 파싱 → kid:PublicKey 맵 반환.
     * RSA (kty=RSA) 키만 처리한다.
     */
    private Map<String, PublicKey> parseJwks(String json) throws Exception {
        Map<String, PublicKey> result = new ConcurrentHashMap<>();
        JsonNode root = objectMapper.readTree(json);
        JsonNode keys = root.get("keys");

        if (keys == null || !keys.isArray()) {
            throw new RuntimeException("Invalid JWKS format: 'keys' array not found");
        }

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        for (JsonNode key : keys) {
            String kty = nodeText(key, "kty");
            if (!"RSA".equalsIgnoreCase(kty)) {
                continue; // EC 등 비-RSA 키 스킵
            }

            String kid = nodeText(key, "kid");
            String n   = nodeText(key, "n");
            String e   = nodeText(key, "e");

            if (kid == null || n == null || e == null) {
                log.warn("Skipping key with missing kid/n/e fields");
                continue;
            }

            try {
                BigInteger modulus  = new BigInteger(1, Base64.getUrlDecoder().decode(n));
                BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
                PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
                result.put(kid, publicKey);
                log.debug("Loaded RSA key kid={}", kid);
            } catch (Exception ex) {
                log.warn("Failed to parse key kid={}: {}", kid, ex.getMessage());
            }
        }

        return result;
    }

    private String nodeText(JsonNode node, String fieldName) {
        JsonNode field = node.get(fieldName);
        return (field != null && !field.isNull()) ? field.asText() : null;
    }
}
