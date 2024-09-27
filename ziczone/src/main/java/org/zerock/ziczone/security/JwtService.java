package org.zerock.ziczone.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.zerock.ziczone.domain.member.User;
import org.zerock.ziczone.repository.member.UserRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@Component
@RequiredArgsConstructor
@Service
@Transactional
@Log4j2
public class JwtService {

    private final UserRepository userRepository;

    // 토큰의 유효기간
    static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 14; // 14일
//    static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 30; // 14일
    static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30; // 30분
//    static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 15; // 임시(15초)
    static final String PREFIX = "Bearer "; // 토큰을 빨리 찾기 위해 붙여주는 문자열
    static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256); // 비밀키

    // 비밀키로 서명된 JWT토큰 발급
    public Map<String, String> getToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String role = user.getUserType().toString();
        Long userId = user.getUserId();

        String refreshToken = Jwts.builder()
                        .setSubject(email)
                        .claim("role", role)
                        .claim("userId", userId)
                        .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRE_TIME))
                        .signWith(key)
                        .compact();

        String accessToken = Jwts.builder()
                        .setSubject(email)
                        .claim("role", role)
                        .claim("userId", userId)
                        .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRE_TIME))
                        .signWith(key)
                        .compact();

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);

        saveRefreshToken(email, refreshToken);
        return tokens;
    }

    // RefreshToken DB에 저장
    public void saveRefreshToken(String email, String refreshToken) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        User updateUser = user.toBuilder().refreshToken(refreshToken).build();
        userRepository.save(updateUser);

    }

    public String refreshAccessToken(String accessToken, String refreshToken) {
        try {
            // 로그 추가: Access token에서 사용자 정보 추출 시 로그 출력
            log.info("Extracting user information from access token");
            String userEmailFromAccess = extractUsername(accessToken);
            Long userIdFromAccess = extractUserId(accessToken);
            log.info("Access token info: userEmail={}, userId={}", userEmailFromAccess, userIdFromAccess);

            // 로그 추가: DB에 저장된 refreshToken이 유효한지 확인하는 부분
            log.info("Looking for user with refresh token");
            User user = userRepository.findByRefreshToken(refreshToken)
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));

            // 로그 추가: 같은 사용자인지 확인
            log.info("Validating if tokens belong to the same user");
            if (!userEmailFromAccess.equals(user.getEmail()) || !userIdFromAccess.equals(user.getUserId())) {
                log.error("Tokens do not match: accessToken user={}, refreshToken user={}", userEmailFromAccess, user.getEmail());
                throw new IllegalArgumentException("Tokens do not match for the same user");
            }

            // 로그 추가: Refresh Token 만료 확인
            log.info("Checking if refresh token is expired");
            if (isTokenExpired(refreshToken)) {
                log.error("Refresh token is expired for user={}", userEmailFromAccess);
                throw new IllegalArgumentException("Refresh token is expired");
            }

            // 로그 추가: 새로운 Access Token 발급
            log.info("Generating new access token");
            return Jwts.builder()
                    .setSubject(user.getEmail())
                    .claim("role", user.getUserType())
                    .claim("userId", user.getUserId())
                    .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRE_TIME))
                    .signWith(key)
                    .compact();

        } catch (ExpiredJwtException e) {
            // 로그 추가: Access Token이 만료된 경우 처리
            log.warn("Access token expired: {}", e.getMessage());

            // 여기서 Refresh Token으로 새로운 Access Token 발급\
            User user = userRepository.findByRefreshToken(refreshToken)
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));

            if (isTokenExpired(refreshToken)) {
                log.error("Refresh token is expired during access token renewal for user={}", user.getEmail());
                throw new IllegalArgumentException("Refresh token is expired");
            }

            return Jwts.builder()
                    .setSubject(user.getEmail())
                    .claim("role", user.getUserType())
                    .claim("userId", user.getUserId())
                    .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRE_TIME))
                    .signWith(key)
                    .compact();
        }
    }

    // 클라이언트가 보내온 요청 헤더에서, 토큰을 확인하고 사용자 이름으로 전환함(로그인이외의 다른 컨트롤러에서 적절하게 사용해야함)
    public String getAuthUser(HttpServletRequest request) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);

        // 토큰이 헤더에 존재한다면
        if (token != null && token.startsWith(PREFIX)) {
            // token을 비밀키로 풀었을 때 user가 잘 추출되면
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token.replace(PREFIX, ""))
                    .getBody()
                    .getSubject();
        }
        return null;
    }

    // 토큰에서 모든 클레임 추출
    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token.replace(PREFIX, ""))
                .getBody();
    }

    // 특정 클레임 추출
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // 토큰에서 사용자 이름 추출
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // 토큰에서 역할 추출
    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    // 토큰에서 사용자 ID 추출
    public Long extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", Long.class));
    }

    // 토큰 만료 여부 확인
    public Boolean isTokenExpired(String token) {
        try {
            return extractClaim(token, Claims::getExpiration).before(new Date());
        } catch (ExpiredJwtException e) {
            log.error("Token is expired: {}", e.getMessage());
            return true; // 만료된 토큰임을 명시적으로 반환
        } catch (Exception e) {
            log.error("Error extracting claims from token: {}", e.getMessage());
            return true; // 안전하게 처리하기 위해 true 반환 (예외가 발생하면 만료된 것으로 처리)
        }
    }

    // 토큰 유효성 검증
    public Boolean validateToken(String token, String username) {
        final String extractedUsername = extractUsername(token);
        return (extractedUsername.equals(username) && !isTokenExpired(token));
    }
}