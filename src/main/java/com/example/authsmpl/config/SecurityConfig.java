package com.example.authsmpl.config;

import com.example.authsmpl.filter.JwtAuthenticationFilter;
import com.example.authsmpl.service.JwksService;
import com.example.authsmpl.service.JwtValidationService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Instant;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtValidationService jwtValidationService;
    private final JwksService jwksService;

    public SecurityConfig(JwtValidationService jwtValidationService, JwksService jwksService) {
        this.jwtValidationService = jwtValidationService;
        this.jwksService = jwksService;
        // 애플리케이션 기동 시 공개키 사전 로드
        jwksService.preload();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // REST API 는 CSRF 불필요
            .csrf(AbstractHttpConfigurer::disable)

            // 세션 사용 안 함 (Stateless)
            .sessionManagement(sm ->
                sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // 모든 요청에 인증 필요
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )

            // JWT 필터를 UsernamePasswordAuthenticationFilter 앞에 삽입
            .addFilterBefore(
                new JwtAuthenticationFilter(jwtValidationService),
                UsernamePasswordAuthenticationFilter.class
            )

            // 인증 실패(401) 핸들러 - 필터에서 이미 처리하지만 안전망으로 설정
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write(
                        "{\"status\":401,\"error\":\"Unauthorized\"," +
                        "\"message\":\"Authentication required\"," +
                        "\"timestamp\":\"" + Instant.now() + "\"}"
                    );
                })
                // 인가 실패(403) 핸들러
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write(
                        "{\"status\":403,\"error\":\"Forbidden\"," +
                        "\"message\":\"Access denied\"," +
                        "\"timestamp\":\"" + Instant.now() + "\"}"
                    );
                })
            );

        return http.build();
    }
}
