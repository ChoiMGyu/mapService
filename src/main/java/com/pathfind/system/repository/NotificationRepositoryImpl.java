/*
 * 클래스 기능 : 알림 리포지토리 구현체
 * 최근 수정 일자 : 2024.05.28(화)
 */
package com.pathfind.system.repository;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pathfind.system.notificationServiceDomain.Notification;
import com.pathfind.system.service.RedisUtil;
import com.pathfind.system.service.RedisValue;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import java.util.*;

@Repository
@RequiredArgsConstructor
public class NotificationRepositoryImpl implements NotificationRepository {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final RedisUtil redisUtil;

    private final ObjectMapper objectMapper;

    @Override
    public void saveNotificationCache(String userId, Notification notification) {
        logger.info("Save notification...");
        List<Notification> notifications = findAllNotificationCacheByUserId(userId);
        notifications.add(notification);
        try {
            String jsonStringNotifications = objectMapper.writeValueAsString(notifications);
            redisUtil.setData(userId + "Notification", jsonStringNotifications);
        } catch (JsonProcessingException e) {
            logger.warn(e.getMessage());
        }
    }

    @Override
    public void saveAllNotificationCache(String userId, List<Notification> notifications) {
        logger.info("Save all notifications...");
        try {
            String jsonStringNotifications = objectMapper.writeValueAsString(notifications);
            redisUtil.setData(userId + "Notification", jsonStringNotifications);
        } catch (JsonProcessingException e) {
            logger.warn(e.getMessage());
        }
    }

    @Override
    public List<Notification> findAllNotificationCacheByUserId(String userId) {
        logger.info("Get all notifications by userId");
        String jsonStringNotifications = redisUtil.getData(userId + "Notification");
        try {
            return objectMapper.readValue(jsonStringNotifications, new TypeReference<ArrayList<Notification>>() {
            });
        } catch (Exception e) {
            logger.warn(e.getMessage());
        }
        return new ArrayList<>();
    }

    @Override
    public void deleteAllNotificationCacheByUserId(String userId) {
        logger.info("Delete all notifications by userId");
        redisUtil.deleteData(userId + "Notification");
    }

    @Override
    public void deleteAllNotificationCacheByRoomId(String roomId) {
        logger.info("Delete all notifications by roomId");
        ValueOperations<String, String> allData = redisUtil.getAllData();
        Set<String> keys = allData.getOperations().keys(RedisValue.GET_ALL_DATA);
        if (keys == null) return;
        for (String key : keys) {
            if (!key.contains("Notification")) continue;
            deleteNotificationByRoomIdAndUserId(roomId, key.replace("Notification", ""));
        }
    }

    @Override
    public void deleteNotificationByRoomIdAndUserId(String roomId, String userId) {
        List<Notification> notifications = findAllNotificationCacheByUserId(userId);
        Iterator<Notification> iter = notifications.iterator();
        while (iter.hasNext()) {
            Notification notification = iter.next();
            if (notification.getRoomId() != null && roomId.equals(notification.getRoomId())) iter.remove();
        }
        if (notifications.isEmpty()) {
            deleteAllNotificationCacheByUserId(userId);
        } else {
            saveAllNotificationCache(userId, notifications);
        }
    }
}
