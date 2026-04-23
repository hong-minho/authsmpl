package com.example.authsmpl.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    /**
     * GET /test
     * Authorization 헤더 검증 통과 시 "ok" 반환.
     *
     * @param subject SecurityContext 에서 주입된 인증된 사용자 principal (sub 클레임)
     */
    @GetMapping("/test")
    public ResponseEntity<String> test(@AuthenticationPrincipal String subject) {
        return ResponseEntity.ok("ok");
    }
}
