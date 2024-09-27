package org.zerock.ziczone.security;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


//JWT토큰을 검증하고 사용자 정보를 설정하는 역할
@Log4j2
@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;

    // doFilterInternal : 요청을 처리하고 필터 체인을 통해 다음 필터로 전달하는 역할
    // request : 클라이언트의 HTTP요청
    // response : 서버가 클라이언트로 보내는 응답
    // chain : 필터 체인의 다음 필터를 호출
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        // refresh token 재발급 요청(/api/token/refresh)은 필터링하지 않음
        if (request.getRequestURI().equals("/api/token/refresh")) {
            chain.doFilter(request, response);
            return;
        }
        //Authorization헤더에서 JWT토큰 추출
        final String authorizationHeader = request.getHeader("Authorization");

        //username, jwt 초기화
        String username = null;
        String jwt = null;

        log.info("Request URI: {}", request.getRequestURI());
        log.info("Authorization Header: {}", authorizationHeader);

        //헤더가 존재하고 ziczone으로 시작하는 경우, 토큰에서 username추출
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            try {
                username = jwtService.extractUsername(jwt); // 토큰에서 사용자 이름 추출(email)
            } catch (ExpiredJwtException e) {
                // AccessToken 만료 시 클라이언트에 만료되었음을 알림
                log.info("AccessToken 만료됨");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access token expired");
                return; // 필터 체인을 멈추고 응답을 종료
            }
        }

        // 사용자이름이 존재하고, 현재 SecurityContext에 인증정보가 없다면(정상토큰일 경우 실행)
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // UserDetails를 로드
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            //토큰이 유효하지 않을 경우
            if (!jwtService.validateToken(jwt, userDetails.getUsername())) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access token expired");
                return;
            }
            // 토큰이 유효할 경우 : 사용자 정보를 바탕으로 UsernamePasswordAuthenticationToken을 생성
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, "", userDetails.getAuthorities());

            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        //다음 필터를 호출
        chain.doFilter(request, response);
    }
}
