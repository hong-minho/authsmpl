# authsmpl

JDK 21 + Spring Boot 3.3 기반 ADFS JWT 인증 REST API 샘플 프로젝트

---

## 프로젝트 구조

```
authsmpl/
├── pom.xml
└── src/main/
    ├── resources/
    │   └── application.yml
    └── java/com/example/authsmpl/
        ├── AuthsmplApplication.java
        ├── config/
        │   ├── AdfsProperties.java          ← yml 설정 바인딩
        │   └── SecurityConfig.java          ← Spring Security 필터 체인
        ├── filter/
        │   └── JwtAuthenticationFilter.java ← Bearer 토큰 추출 및 검증
        ├── service/
        │   ├── JwksService.java             ← JWKS 공개키 메모리 캐시
        │   └── JwtValidationService.java    ← JWT 검증 (서명/만료/iss/aud)
        └── controller/
            └── TestController.java          ← GET /test → "ok"
```

---

## 기술 스택

| 항목 | 버전 |
|------|------|
| JDK | 21 |
| Spring Boot | 3.3.0 |
| Spring Security | 6.x |
| JJWT | 0.12.5 |
| Jackson | Spring Boot 기본 |

---

## 인증 흐름

```
클라이언트 요청
  └─ Authorization: Bearer <token>
        │
        ▼
JwtAuthenticationFilter
  ├─ 헤더 없음 → 401 반환
  ├─ kid 추출 (JWT 헤더 파싱)
  │
  ▼
JwksService (메모리 캐시)
  ├─ 캐시 히트 → PublicKey 반환
  └─ 캐시 미스 + 쿨다운 경과 → ADFS JWKS 재조회 후 캐시 갱신
        │
        ▼
JwtValidationService
  ├─ RS256 서명 검증
  ├─ exp (만료시간) 검증
  ├─ iss (발급자) 검증
  ├─ aud (대상) 검증
  ├─ 실패 → 401 JSON 응답
  └─ 성공 → SecurityContext 등록 → 다음 필터
        │
        ▼
GET /test → "ok"
```

---

## ADFS 설정

| 항목 | 값 |
|------|----|
| ADFS 서버 | `https://adfs-server.net/adfs` |
| JWKS URI | `https://adfs-server.net/adfs/discovery/keys` |

---

## 시작 전 필수 설정

`src/main/resources/application.yml` 에서 아래 값을 환경에 맞게 수정합니다.

```yaml
adfs:
  issuer: https://adfs-server.net/adfs
  jwks-uri: https://adfs-server.net/adfs/discovery/keys
  audience: your-client-id-here        # ← ADFS 앱 등록 Client ID로 교체
  jwks-refresh-cooldown-seconds: 300   # 공개키 재조회 쿨다운 (초)
```

---

## 빌드 및 실행

```bash
# 빌드
./mvnw clean package

# 실행
java -jar target/authsmpl-0.0.1-SNAPSHOT.jar
```

---

## API 테스트

```bash
# 인증 성공
curl -H "Authorization: Bearer <valid_token>" http://localhost:8080/test

# 인증 실패 (헤더 없음) → 401
curl http://localhost:8080/test
```

### 401 응답 예시

```json
{
  "status": 401,
  "error": "Unauthorized",
  "message": "Authorization header is missing or invalid",
  "timestamp": "2026-04-23T10:00:00Z"
}
```

---

## 참고 사항

- ADFS 사설 CA 인증서 사용 시 JVM TrustStore에 인증서 등록 필요
- 공개키는 메모리 캐시에 보관되며, `kid` 불일치 시 쿨다운 경과 후 자동 갱신
- 세션 미사용 (Stateless), CSRF 비활성화
