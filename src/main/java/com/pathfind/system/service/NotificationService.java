/*
 * 클래스 기능 : 알림 서비스 인터페이스
 * 최근 수정 일자 : 2024.05.28(화)
 */
package com.pathfind.system.service;

import com.pathfind.system.notificationServiceDomain.NotificationType;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

public interface NotificationService {
    public SseEmitter subscribe(String userId);

    public void sendInviteNotification(String content, String sender, String receiver, NotificationType notificationType, String url, String roomId);

    public void sendAllNotificationByUserId(String sseEmitterId, SseEmitter sseEmitter, String userId);

    public void deleteAllNotificationByRoomId(String roomId);

    public void changeAllReadTypeToReadByUserId(String userId);

    void deleteNotificationByRoomIdAndUserId(String roomId, String userId);
}
