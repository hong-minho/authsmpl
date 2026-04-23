package com.example.authsmpl.filter;

import com.example.authsmpl.service.JwtValidationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * JWT Bearer 토큰 인증 필터.
 *
 * <pre>
 * 처리 흐름:
 * 1. Authorization 헤더에서 "Bearer <token>" 추출
 * 2. JwtValidationService 를 통해 토큰 검증
 * 3. 성공 → SecurityContext 에 Authentication 등록 후 다음 필터로 전달
 * 4. 실패 → HTTP 401 + JSON 에러 응답 반환 (필터 체인 중단)
 * </pre>
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtValidationService jwtValidationService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtAuthenticationFilter(JwtValidationService jwtValidationService) {
        this.jwtValidationService = jwtValidationService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // ── 1. Authorization 헤더 없음 ────────────────────────────────────────
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            log.debug("Missing or malformed Authorization header for {}", request.getRequestURI());
            sendUnauthorized(response, "Authorization header is missing or invalid");
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();

        // ── 2. JWT 검증 ────────────────────────────────────────────────────────
        try {
            Claims claims = jwtValidationService.validate(token);

            // ── 3. SecurityContext 에 인증 정보 등록 ──────────────────────────
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            claims.getSubject(),
                            null,
                            List.of(new SimpleGrantedAuthority("ROLE_USER"))
                    );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("Authentication set for sub={}", claims.getSubject());
            filterChain.doFilter(request, response);

        } catch (JwtValidationService.JwtAuthException e) {
            log.warn("JWT validation failed for {}: {}", request.getRequestURI(), e.getMessage());
            SecurityContextHolder.clearContext();
            sendUnauthorized(response, e.getMessage());
        }
    }

    // ── 401 응답 헬퍼 ─────────────────────────────────────────────────────────

    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> body = Map.of(
                "status", 401,
                "error", "Unauthorized",
                "message", message,
                "timestamp", Instant.now().toString()
        );

        objectMapper.writeValue(response.getWriter(), body);
    }
}
