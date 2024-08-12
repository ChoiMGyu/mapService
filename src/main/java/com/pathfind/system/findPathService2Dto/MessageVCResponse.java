/*
 * 클래스 기능 : stomp websocket 에서 주고 받는 메시지 포멧을 정의한 dto 이다.
 * 최근 수정 일자 : 2024.04.11(목)
 */
package com.pathfind.system.findPathService2Dto;

import com.pathfind.system.findPathDto.VertexInfo;
import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Builder(builderMethodName = "innerBuilder")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
public class MessageVCResponse {
    private String roomId;
    private String sender;
    private String manager;
    private MessageType msgType;
    private String message;
    private String owner;
    private int curMemberNum;
    private LocalDateTime roomRemainingTime;
    private List<List<VertexInfo>> route;

    public static MessageVCResponseBuilder builder(String roomId, MessageType messageType) {
        return innerBuilder().roomId(roomId).msgType(messageType);
    }
}
