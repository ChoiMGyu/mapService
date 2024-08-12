/*
 * 클래스 기능 : Stomp 메시지 전송 서비스 구현체
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.service;

import com.pathfind.system.findPathDto.VertexInfo;
import com.pathfind.system.findPathService2Dto.MessageType;
import com.pathfind.system.findPathService2Dto.MessageVCResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SendStompMessageServiceImpl implements SendStompMessageService {

    private final SimpMessagingTemplate template;

    @Override
    public void sendEnter(String roomId, String sender, String message, int curMemberNum, LocalDateTime roomRemainingTime) {
        MessageVCResponse response = MessageVCResponse.builder(roomId, MessageType.ENTER)
                .sender(sender)
                .message(message)
                .curMemberNum(curMemberNum)
                .roomRemainingTime(roomRemainingTime)
                .build();
        template.convertAndSend("/sub/service2/room/" + roomId, response);
    }

    @Override
    public void sendLeave(String roomId, String sender, String manager, String message, int curMemberNum, LocalDateTime roomRemainingTime) {
        MessageVCResponse response = MessageVCResponse.builder(roomId, MessageType.LEAVE)
                .sender(sender)
                .manager(manager)
                .message(message)
                .curMemberNum(curMemberNum)
                .roomRemainingTime(roomRemainingTime)
                .build();
        template.convertAndSend("/sub/service2/room/" + roomId, response);
    }

    @Override
    public void sendExpired(String roomId, String message) {
        MessageVCResponse response = MessageVCResponse.builder(roomId, MessageType.ROOM_EXPIRED)
                .message(message)
                .build();
        template.convertAndSend("/sub/service2/room/" + roomId, response);
    }

    @Override
    public void sendRoute(String roomId, String sender, List<List<VertexInfo>> route) {
        MessageVCResponse response = MessageVCResponse.builder(roomId, MessageType.ROUTE)
                .sender(sender)
                .route(route)
                .build();
        template.convertAndSend("/sub/service2/room/" + roomId, response);
    }

    @Override
    public void sendNotInCampus(String roomId, String sender, String message) {
        MessageVCResponse response = MessageVCResponse.builder(roomId, MessageType.NOT_IN_CAMPUS)
                .sender(sender)
                .message(message)
                .build();
        template.convertAndSend("/sub/service2/room/" + roomId, response);
    }

    @Override
    public void sendChangeOwner(String roomId, String sender, String message, String owner) {
        MessageVCResponse response = MessageVCResponse.builder(roomId, MessageType.CHANGE_OWNER)
                .sender(sender)
                .message(message)
                .owner(owner)
                .build();
        template.convertAndSend("/sub/service2/room/" + roomId, response);
    }
}
