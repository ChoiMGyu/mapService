/*
 * 클래스 기능 : 알림 레포지토리 인터페이스
 * 최근 수정 일자 : 2024.05.28(화)
 */
package com.pathfind.system.repository;

import com.pathfind.system.notificationServiceDomain.Notification;

import java.util.List;

public interface NotificationRepository {

    public void saveNotificationCache(String userId, Notification notification);

    public void saveAllNotificationCache(String userId, List<Notification> notifications);

    public List<Notification> findAllNotificationCacheByUserId(String userId);

    public void deleteAllNotificationCacheByUserId(String userId);

    public void deleteAllNotificationCacheByRoomId(String roomId);

    public void deleteNotificationByRoomIdAndUserId(String roomId, String userId);
}
