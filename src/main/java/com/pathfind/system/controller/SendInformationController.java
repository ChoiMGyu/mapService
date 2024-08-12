/*
 * 클래스 기능 : stomp websocket에서 /pub으로 발행된 메시지를 받아 가공하여 같은 방의 인원들에게 전달하는 클래스이다.
 * 최근 수정 일자 : 2024.05.29(수)
 */
package com.pathfind.system.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pathfind.system.domain.Member;
import com.pathfind.system.findPathDto.VertexInfo;
import com.pathfind.system.findPathService2Domain.*;
import com.pathfind.system.findPathService2Dto.*;
import com.pathfind.system.service.FindPathRoomService;
import com.pathfind.system.service.MemberService;
import com.pathfind.system.service.SendStompMessageService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.GenericMessage;
import org.springframework.stereotype.Controller;
import org.springframework.web.socket.messaging.*;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;


@Controller
@RequiredArgsConstructor
public class SendInformationController {

    private static final Logger logger = LoggerFactory.getLogger(SendInformationController.class);

    private final ObjectMapper objectMapper;
    private final FindPathRoomService findPathRoomService;
    private final SendStompMessageService sendStompMessageService;
    private final MemberService memberService;

    @EventListener
    public void handelWebSocketConnectEvent(SessionConnectEvent event) throws IOException {
        logger.info("Connect message를 서버로 전송");
        StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
        String roomId = Objects.requireNonNull(headerAccessor.getNativeHeader("roomId")).get(0);
        String sender = Objects.requireNonNull(headerAccessor.getNativeHeader("sender")).get(0);
        // stomp Connect 메시지 헤더에 roomId와 id 값이 포함되어 있지 않으면 개발자가 의도한 것이 아니므로 함수를 종료한다.
        if (roomId == null || sender == null) return;

        Objects.requireNonNull(headerAccessor.getSessionAttributes()).put("roomId", roomId);
        Objects.requireNonNull(headerAccessor.getSessionAttributes()).put("sender", sender);
        logger.info("Connect header information: {}", headerAccessor);
    }

    @EventListener
    public void handleWebSocketConnectedListener(SessionConnectedEvent event) throws IOException {
        logger.info("Connected message를 서버로부터 전달받음");
        StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
        logger.info("Connected header information: {}", headerAccessor);

        GenericMessage simpConnectMessage = (GenericMessage) headerAccessor.getMessageHeaders().get("simpConnectMessage");
        Map simpSessionAttributes = (Map) simpConnectMessage.getHeaders().get("simpSessionAttributes");
        String sender = simpSessionAttributes.get("sender").toString();
        String roomId = simpSessionAttributes.get("roomId").toString();

        //sender가 누군지 확인하고
        FindPathRoom beforeHasRoom = findPathRoomService.leaveRoom(sender);
        //이미 접속하고 있는 방이 존재하는지 확인
        if (beforeHasRoom == null) return;

        //방이 존재하므로 해당 방을 퇴장한다는 메시지를 전송
        if (beforeHasRoom.isNoOneInRoom()) {
            logger.info("{}의 퇴장으로 방에 아무도 남지 않았으므로 방을 삭제합니다.", sender);
            findPathRoomService.deleteRoom(beforeHasRoom.getRoomId());
            sendStompMessageService.sendExpired(beforeHasRoom.getRoomId(), "방에 아무도 존재하지 않아 방이 종료되었습니다.");
            return;
        }

        Member member = Member.createMember(sender, null, null, null, null);
        List<Member> memberList = memberService.findByUserId(member);

        if (memberList.isEmpty()) return;

        member = memberList.get(0);

        sendStompMessageService.sendLeave(beforeHasRoom.getRoomId(), sender, beforeHasRoom.getOwnerUserId(), member.getNickname() + "님이 길 찾기 방에서 퇴장하였습니다.", beforeHasRoom.getCurMemberNum(), beforeHasRoom.getRoomRemainingTime());
    }

    @EventListener
    public void handleWebSocketSubscribeListener(SessionSubscribeEvent event) throws IOException {
        logger.info("Subscribe message를 서버로 전송");
        StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
        String sender = Objects.requireNonNull(headerAccessor.getSessionAttributes()).get("sender").toString();
        String roomId = Objects.requireNonNull(headerAccessor.getSessionAttributes()).get("roomId").toString();
        logger.info("{}가 {}에 subscribe하였음", sender, roomId);

        Member member = Member.createMember(sender, null, null, null, null);
        List<Member> memberList = memberService.findByUserId(member);

        if (memberList.isEmpty()) return;

        member = memberList.get(0);

        FindPathRoom room = findPathRoomService.memberEnterRoom(roomId, sender, member.getNickname());
        sendStompMessageService.sendEnter(roomId, sender, member.getNickname() + "님이 길 찾기 방에 참여하였습니다.", room.getCurMemberNum(), room.getRoomRemainingTime());
    }

    @EventListener
    public void handleWebSocketUnsubscibeListener(SessionUnsubscribeEvent event) {
        StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
        logger.info("{}가 {}에 Unsubscribe하였음", headerAccessor.getNativeHeader("sender"), headerAccessor.getNativeHeader("roomId"));
    }

    @EventListener
    public void handleWebSocketDisconnectListener(SessionDisconnectEvent event) throws IOException {
        logger.info("Disconnect message를 서버로부터 전달 받음");
        StompHeaderAccessor headerAccessor = StompHeaderAccessor.wrap(event.getMessage());
        logger.info("Disconnect header information: {}", headerAccessor);

        String sender = Objects.requireNonNull(headerAccessor.getSessionAttributes()).get("sender").toString();
        String roomId = Objects.requireNonNull(headerAccessor.getSessionAttributes()).get("roomId").toString();
        //Disconnect 유저(sender)와 방(roomId)을 전달받고

        Member member = Member.createMember(sender, null, null, null, null);
        List<Member> memberList = memberService.findByUserId(member);

        if (memberList.isEmpty()) return;

        member = memberList.get(0);

        //나갈 방을 찾은 후
        //sender는 방을 나가고 추가적인 동작(방장을 업데이트 또는 방을 없앰)을 한다
        FindPathRoom curRoom = findPathRoomService.leaveRoom(sender, roomId);

        if (curRoom == null) return;

        if (curRoom.isNoOneInRoom()) {
            //sender가 방을 나가면서 방에 아무도 남지 않는 경우 방을 삭제한다
            logger.info("{}의 퇴장으로 방에 아무도 남지 않았으므로 방을 삭제합니다.", sender);
            findPathRoomService.deleteRoom(roomId);
            sendStompMessageService.sendExpired(roomId, "방에 아무도 존재하지 않아 방이 종료되었습니다.");
            return;
        }

        logger.info("방 인원들에게 퇴장 메시지를 전송합니다.");
        sendStompMessageService.sendLeave(roomId, sender, curRoom.getOwnerUserId(), member.getNickname() + "님이 길 찾기 방에서 퇴장하였습니다.", curRoom.getCurMemberNum(), curRoom.getRoomRemainingTime());
        //sender가 나가도 방에 인원이 남아있으므로 퇴장 메시지를 전송한다
    }

    @MessageMapping(value = "/room/route")
    public void getRoute(MessageVCRequest message) throws IOException {
        //고친 부분 없음
        FindPathRoom room = findPathRoomService.findRoomById(message.getRoomId());

        if (room == null) {
            logger.info("Room deleted because the time assigned for the room has expired. roomId: {}", message.getRoomId());
            sendStompMessageService.sendExpired(message.getRoomId(), "방에 할당된 두 시간이 만료되어 방이 종료되었습니다.");
            return;
        }

        Member member = Member.createMember(message.getSender(), null, null, null, null);
        List<Member> memberList = memberService.findByUserId(member);
        logger.info("message sender: {}", message.getSender());
        if (memberList.isEmpty()) return;

        member = memberList.get(0);

        if (room.findMemberByUserId(message.getSender()) == null) {
            logger.info("{} leaves room, roomId: {}", message.getSender(), message.getRoomId());
            sendStompMessageService.sendLeave(message.getRoomId(), message.getSender(), room.getOwnerUserId(), member.getNickname() + "님이 길 찾기 방에서 퇴장하였습니다.", room.getCurMemberNum(), room.getRoomRemainingTime());
            return;
        }

        room = findPathRoomService.changeRoomMemberLocation(message.getRoomId(), message.getSender(), objectMapper.readValue(message.getMessage(), MemberLatLng.class));

        if (message.getSender().equals(room.getOwnerUserId())) {
            if (LocalDateTime.now().isAfter(room.getRoomDeletionTime())) {
                logger.info("Room deleted because no one came to the room for 5 minutes. roomId: {}", message.getRoomId());
                sendStompMessageService.sendExpired(message.getRoomId(), "5분간 아무도 들어오지 않아 방이 종료되었습니다.");
                return;
            }
        } else if (LocalDateTime.now().isAfter(room.findMemberByUserId(message.getSender()).getRoomExitTime())) {
            logger.info("{} leaves room because he doesn't move for 10 minutes, roomId: {}", message.getSender(), message.getRoomId());

            room = findPathRoomService.leaveRoom(message.getSender(), message.getRoomId());
            sendStompMessageService.sendLeave(message.getRoomId(), message.getSender(), room.getOwnerUserId(), member.getNickname() + "님이 10분간 움직이지 않아 방에서 퇴장되었습니다.", room.getCurMemberNum(), room.getRoomRemainingTime());
            return;
        }

        List<ShortestPathRouteCSResponse> result = findPathRoomService.findShortestRoute(room);

        List<List<VertexInfo>> routeResult = new ArrayList<>();
        //logger.info("result.size(): {}", result.size());
        for (ShortestPathRouteCSResponse info : result) {
            if (message.getSender().equals(info.getUserId()) && info.getDistance() < RoomValue.NAVIGATION_STOPPING_DISTANCE) {
                room = findPathRoomService.leaveRoom(message.getSender());
                sendStompMessageService.sendLeave(message.getRoomId(), message.getSender(), room.getOwnerUserId(), member.getNickname() + "님과의 거리가 가까워 길 찾기가 종료되었습니다.", room.getCurMemberNum(), room.getRoomRemainingTime());
                continue;
            }
            routeResult.add(info.getRoute());
        }
        sendStompMessageService.sendRoute(message.getRoomId(), message.getSender(), routeResult);
        // logger.info("route result: {}", message);
    }

    @MessageMapping(value = "/room/delete")
    public void deleteRoom(MessageVCRequest message) throws IOException {
        logger.info("{}가 {} 방을 삭제하였음.", message.getSender(), message.getRoomId());

        FindPathRoom room = findPathRoomService.findRoomById(message.getRoomId());

        if (room == null) {
            logger.info("Room deleted because the time assigned for the room has expired. roomId: {}", message.getRoomId());
            sendStompMessageService.sendExpired(message.getRoomId(), "방에 할당된 두 시간이 만료되어 방이 종료되었습니다.");
            return;
        }

        Member member = Member.createMember(message.getSender(), null, null, null, null);
        List<Member> memberList = memberService.findByUserId(member);

        if (memberList.isEmpty()) return;

        member = memberList.get(0);

        //올바른 상황에서 호출된다고 하면 이전의 작성된 로직은 필요가 없다고 생각하였음
        //room == null이어서 return이 되는 상황은 애초에 "/room/delete"가 호출되면 안되는 상황임
        sendStompMessageService.sendExpired(message.getRoomId(), member.getNickname() + "님이 길 찾기 방을 삭제하였습니다.");
        findPathRoomService.deleteRoom(message.getRoomId());
    }

    @MessageMapping(value = "/room/out-campus")
    public void sendNotInCampus(MessageVCRequest message) throws IOException {
        logger.info("{} send message to the room, roomId: {}", message.getSender(), message.getRoomId());

        FindPathRoom room = findPathRoomService.findRoomById(message.getRoomId());

        if (room == null) {
            logger.info("Room deleted because the time assigned for the room has expired. roomId: {}", message.getRoomId());
            sendStompMessageService.sendExpired(message.getRoomId(), "방에 할당된 두 시간이 만료되어 방이 종료되었습니다.");
            return;
        }

        //위와 마찬가지의 이유로 "/room/out-campus"가 올바른 상황에 만들어지면 room == null일 경우가 없음
        sendStompMessageService.sendNotInCampus(message.getRoomId(), message.getSender(), message.getMessage());
    }

    @MessageMapping(value = "/room/changeOwner")
    public void sendChangeOwner(MessageVCRequest message) throws IOException {
        logger.info("MessageMapping changeOwner 호출");

        FindPathRoom room = findPathRoomService.findRoomById(message.getRoomId());

        if (room == null) {
            logger.info("Room deleted because the time assigned for the room has expired. roomId: {}", message.getRoomId());
            sendStompMessageService.sendExpired(message.getRoomId(), "방에 할당된 두 시간이 만료되어 방이 종료되었습니다.");
            return;
        }

        Member member = Member.createMember(message.getSender(), null, null, null, null);
        List<Member> memberList = memberService.findByUserId(member);

        if (memberList.isEmpty()) return;

        member = memberList.get(0);

        findPathRoomService.changeOwnerUserId(room.getRoomId(), message.getOwner());

        sendStompMessageService.sendChangeOwner(message.getRoomId(), member.getUserId(), "현재 방의 방장이 바뀌었습니다.", message.getOwner());
    }

    @MessageMapping(value = "/room/leaveRoomUserId")
    public void sendLeaveRoomUserId(MessageVCRequest message) throws IOException {
        logger.info("MessageMapping sendLeaveRoomUserId 호출");

        FindPathRoom room = findPathRoomService.findRoomById(message.getRoomId());

        if (room == null) {
            logger.info("Room deleted because the time assigned for the room has expired. roomId: {}", message.getRoomId());
            sendStompMessageService.sendExpired(message.getRoomId(), "방에 할당된 두 시간이 만료되어 방이 종료되었습니다.");
            return;
        }

        Member member = Member.createMember(message.getSender(), null, null, null, null);
        List<Member> memberList = memberService.findByUserId(member);

        if (memberList.isEmpty()) return;

        member = memberList.get(0);

        room.leaveRoomCurMember(member.getUserId());

        sendStompMessageService.sendLeave(message.getRoomId(), member.getUserId(), room.getOwnerUserId(), member.getNickname() + "님이 길 찾기 방에서 퇴장하였습니다.", room.getCurMemberNum(), room.getRoomRemainingTime());
    }
}
