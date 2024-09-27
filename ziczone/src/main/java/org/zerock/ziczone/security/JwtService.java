package org.zerock.ziczone.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
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
public class JwtService {

    private final UserRepository userRepository;

    // 토큰의 유효기간
    static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 14; // 14일
//    static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30; // 30분
    static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 15; // 임시(15초)
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

    // refresh token, access token 검사하고 accesstoken을 재발급
    public String refreshAccessToken(String accessToken, String refreshToken) {
        // Access token 정보
        String userEmailFromAccess = extractUsername(accessToken);
        Long userIdFromAccess = extractUserId(accessToken);

        // DB에 refreshToken이 저장되어있는지 확인
        User user = userRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // 같은 사용자의 token인지 확인
        if(!userEmailFromAccess.equals(user.getEmail()) || !userIdFromAccess.equals(user.getUserId())) {
            throw new IllegalArgumentException("Tokens do not match for the same user");
        }

        // refresh token 만료 확인
        if(isTokenExpired(refreshToken)) {
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
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    // 토큰 유효성 검증
    public Boolean validateToken(String token, String username) {
        final String extractedUsername = extractUsername(token);
        return (extractedUsername.equals(username) && !isTokenExpired(token));
    }
}