package org.zerock.ziczone.controller;


import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.zerock.ziczone.domain.alarm.Alarm;
import org.zerock.ziczone.dto.Alarm.RequestAlarmDTO;
import org.zerock.ziczone.dto.Alarm.ResponseAlarmDTO;
import org.zerock.ziczone.security.JwtService;
import org.zerock.ziczone.service.alarm.AlarmService;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/sse")
@RequiredArgsConstructor
@Log4j2
public class AlarmSseController {

    private final Map<Long, SseEmitter> sseEmitters = new ConcurrentHashMap<>();
    private final JwtService jwtService;

    private final AlarmService alarmService;

    // 클라이언트 구독
    @GetMapping("/subscribe/{userId}")
    public ResponseEntity<SseEmitter> subscribe(@PathVariable Long userId, @RequestParam("token") String token) {

        return ResponseEntity.ok(alarmService.subscribe(userId, token));
    }

    // 로그인시에 알람 불러오기(알람초기화)
    @GetMapping("/initAlarm/{userId}")
    public ResponseEntity<List<ResponseAlarmDTO>> initAlarm(@PathVariable Long userId) {

        List<ResponseAlarmDTO> responseAlarmDTO = alarmService.AlarmList(userId);
        return ResponseEntity.ok(responseAlarmDTO);
    }

    @PostMapping("/send")
    public void send(){
        alarmService.addAlarm("DELETEBOARD", 1L, 26L);
    }

    // 로그아웃
    @PostMapping("/logout/{userId}")
    public ResponseEntity<String> logout(@PathVariable Long userId) {
        alarmService.logout(userId);
        return ResponseEntity.ok("logout successful");
    }

    //읽음처리
    @PostMapping("/readAlarm/{userId}")
    public ResponseEntity readAlarm(@PathVariable Long userId) {
        alarmService.readAlarm(userId);
        return ResponseEntity.ok("read alarm successful");
    }
}
