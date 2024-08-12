/*
 * 클래스 기능 : Redis 키 만료 event를 추적하는 클래스
 * 최근 수정 일자 : 2024.04.04(수)
 */
package com.pathfind.system.eventListener;

import com.pathfind.system.findPathService2Domain.RoomValue;
import com.pathfind.system.service.NotificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.listener.KeyExpirationEventMessageListener;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.stereotype.Component;

@Component
public class RedisKeyExpiredListener extends KeyExpirationEventMessageListener {

    private static final Logger logger = LoggerFactory.getLogger(RedisKeyExpiredListener.class);

    private final NotificationService notificationService;

    /**
     * Creates new {@link MessageListener} for {@code __keyevent@*__:expired} messages.
     *
     * @param listenerContainer   must not be {@literal null}.
     * @param notificationService
     */
    public RedisKeyExpiredListener(RedisMessageListenerContainer listenerContainer, NotificationService notificationService) {
        super(listenerContainer);
        this.notificationService = notificationService;
    }

    /**
     *
     * @param message   redis key
     * @param pattern   __keyevent@*__:expired
     */
    @Override
    public void onMessage(Message message, byte[] pattern) { // 키 만료 이벤트가 발생하면 동작한다.
        logger.info("########## onMessage pattern " + new String(pattern) + " | " + message.toString());
        if(message.toString().length() != RoomValue.ROOM_ID_LENGTH) return;
        notificationService.deleteAllNotificationByRoomId(message.toString()); // 방 정보 키 값이라면 해당 방과 관련된 알림들을 모두 삭제한다.
    }
}
