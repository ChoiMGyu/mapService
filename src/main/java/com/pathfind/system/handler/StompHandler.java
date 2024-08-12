/*
 * 클래스 기능 : stomp websocket의 헤더를 인터셉트 할 수 있는 클래스이다.
 * 최근 수정 일자 : 2024.03.18(월)
 *//*

package com.pathfind.system.handler;

import com.pathfind.system.service.FindPathRoomService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class StompHandler implements ChannelInterceptor {
    private static final Logger logger = LoggerFactory.getLogger(StompHandler.class);

    private final FindPathRoomService findPathRoomService;

    @Override
    public void postSend(Message<?> message, MessageChannel channel, boolean sent) {
        */
/*logger.info("message: {}", message);
        logger.info("channel: {}", channel);
        logger.info("sent: {}", sent);*//*

        StompHeaderAccessor accessor = StompHeaderAccessor.wrap(message);
        String sessionId = accessor.getSessionId();
        switch (accessor.getCommand()) {
            case CONNECT:
                // 유저가 Websocket으로 connect()를 한 뒤 호출됨
                logger.info("Intercept CONNECT: {}", accessor);
                */
/*Map nativeHeaders = (Map) message.getHeaders().get("nativeHeaders");
                String roomId = (String) ((List) nativeHeaders.get("roomId")).get(0);
                String nickname = (String) ((List) nativeHeaders.get("id")).get(0);
                logger.info("roomId: {}, id: {}",roomId, nickname);
                try {
                    findPathRoomService.setWebSocketSessionId(roomId, nickname, sessionId);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }*//*

                break;
            case SUBSCRIBE:
                logger.info("Intercept SUBSCRIBE: {}", accessor);
                //logger.info("Subscribe event");
                //logger.info("Subscribe header information: {}", accessor);
                */
/*String roomId = accessor.getDestination().replace("/sub/service2/room/", "");
                String nickname = accessor.getSubscriptionId();
                try {
                    findPathRoomService.setWebSocketSessionId(roomId, nickname, sessionId);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }*//*

                break;
            case DISCONNECT:
                // 유저가 Websocket으로 disconnect() 를 한 뒤 호출됨 or 세션이 끊어졌을 때 발생함(페이지 이동~ 브라우저 닫기 등)
                logger.info("Intercept DISCONNECT: {}", accessor);
                //sessionId = accessor.getSessionId(); //(String); message.getHeaders().get("simpSessionId");
                //chatService.sendChatMessage(sessionId);
                break;
            default:
                break;
        }
    }
}
*/
