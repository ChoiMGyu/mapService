/*
 * 클래스 기능 : 알림 기능에 관한 컨트롤러. 사용자가 알림을 구독하거나 확인할 때 사용된다.
 * 최근 수정 일자 : 2024.05.28(화)
 */
package com.pathfind.system.controller;

import com.pathfind.system.service.NotificationService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
@RequiredArgsConstructor
@RequestMapping("/notification")
public class NotificationController {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final NotificationService notificationService;

    @GetMapping(value = "/subscribe")
    public SseEmitter subscribeNotification(@RequestParam(value = "userId") String userId) {
        logger.info("Notification subscribe. id: {}", userId);
        return notificationService.subscribe(userId);
    }

    @GetMapping(value = "/check")
    public void checkAllNotification(@RequestParam(value = "userId") String userId) {
        logger.info("Change all notifications' read type to READ. id: {}", userId);
        notificationService.changeAllReadTypeToReadByUserId(userId);
    }
}
