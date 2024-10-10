package org.zerock.ziczone.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.token.TokenService;
import org.springframework.web.bind.annotation.*;
import org.zerock.ziczone.dto.token.RefreshTokenRequestDTO;
import org.zerock.ziczone.security.JwtService;

import java.util.Map;

@Log4j2
@RestController
@RequestMapping("/api/token")
@RequiredArgsConstructor
public class TokenController {
    private final JwtService jwtService;

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequestDTO refreshTokenRequestDTO,
                                          @CookieValue(value = "refresh_token", required = false) String refreshToken) {

        if (refreshTokenRequestDTO.getAccessToken() == null || refreshToken == null) {
            log.warn("Access token or refresh token is missing");
            return ResponseEntity.badRequest().body(Map.of("message", "Access token and refresh token are required"));
        }

        try {
            String newAccessToken = jwtService.refreshAccessToken(refreshTokenRequestDTO.getAccessToken(), refreshToken);
            log.info("New access token generated successfully");
            return ResponseEntity.ok(Map.of("access_token", newAccessToken));
        } catch (IllegalArgumentException e) {
            log.error("Error during token refresh: {}", e.getMessage());
            return ResponseEntity.status(401).body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            log.error("Unexpected error during token refresh", e);
            return ResponseEntity.status(500).body(Map.of("message", "An unexpected error occurred"));
        }
    }


}
