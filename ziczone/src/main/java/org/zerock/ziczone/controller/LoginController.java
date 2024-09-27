package org.zerock.ziczone.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.zerock.ziczone.domain.member.User;
import org.zerock.ziczone.dto.login.AccountCredentialsDTO;
import org.zerock.ziczone.service.Email.EmailAuthService;
import org.zerock.ziczone.service.join.JoinService;
import org.zerock.ziczone.security.JwtService;
import org.zerock.ziczone.service.login.LoginService;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@Log4j2
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class LoginController {

    private final EmailAuthService emailAuthService;
    private final JoinService joinService;
    private final LoginService loginService;

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager; //비밀번호 자동 비교

    @PostMapping("/login")
    public ResponseEntity<?> getToken(@RequestBody AccountCredentialsDTO accountCredentials) {
        try {
            //인증에 알맞은 객체에 username/password 전달
            UsernamePasswordAuthenticationToken creds = new UsernamePasswordAuthenticationToken(
                    accountCredentials.getEmail(),
                    accountCredentials.getPassword());

            //UserDetailsServiceImpl에 구현한 loadUserByUsername이 호출되어 사용자의 인증을 DB와 확인하여 내부적으로 처리함
            Authentication auth = authenticationManager.authenticate(creds); //인증수행, 성공시 Authentication객체 반환
            SecurityContextHolder.getContext().setAuthentication(auth); //인증에 성공하면, SecurityContextHolder에 인증 정보 설정
                                                                        //현재 요청의 인증 상태를 저장하고 이후 요청에서도 인증정보 사용가능

            // 토큰 발급
            Map<String, String> jwts = jwtService.getToken(auth.getName());
            log.info("Token : " + jwts);
            return ResponseEntity.ok(jwts);
        } catch (BadCredentialsException e) {
            // 아이디나 비밀번호가 틀렸을 때
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Auth Fail", "error", "Invalid email or password"));
        }
    }

    //비밀번호 찾기(메일인증)
    @PostMapping("/login/emailAuth")
    public ResponseEntity<String> sendAuthEmail(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        User EmailDuplication = joinService.EmailDuplication(email);
        if(EmailDuplication != null) {
            emailAuthService.sendVerificationEmail(email);
            return ResponseEntity.ok("email sent");
        }else {
            return ResponseEntity.ok("email empty");
        }
    }

    // 인증코드 검증
    @PostMapping("/login/emailAuth/verify-email")
    public ResponseEntity<String> verifyEmailCode(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String code = request.get("code");
        boolean isVerified = emailAuthService.verifyEmailCode(email, code);
        if (isVerified) {
            return ResponseEntity.ok("Auth Success");
        } else {
            return ResponseEntity.ok("Auth Fail");
        }
    }

    //비밀번호 변경
    @PostMapping("/login/emailAuth/change-password")
    public ResponseEntity<String> changeEmail(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String password = request.get("password");
        User user = joinService.EmailDuplication(email);
        String result = loginService.changePassword(user, password);
        if(result != null) {
            return ResponseEntity.ok("change Password Success");
        }else {
            return ResponseEntity.ok("change Password Fail");
        }
    }

    @PostMapping("/logout")
    public void logout(HttpServletResponse response) {
        // 쿠키 삭제를 위한 설정
        Cookie refreshTokenCookie = new Cookie("refresh_token", null); // 쿠키의 값을 null로 설정
        refreshTokenCookie.setPath("/"); // 쿠키의 경로를 지정
        refreshTokenCookie.setMaxAge(0); // 쿠키의 만료 시간을 0으로 설정하여 즉시 삭제
        refreshTokenCookie.setHttpOnly(true); // HttpOnly 속성 설정
        refreshTokenCookie.setSecure(true); // HTTPS 환경에서만 전송 (옵션)

        response.addCookie(refreshTokenCookie); // 응답에 쿠키 추가 (삭제 요청)
    }
}
