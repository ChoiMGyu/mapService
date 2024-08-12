/*
 * 클래스 기능 : 실시간 상대방 길 찾기 서비스(서비스2)의 페이지들을 렌더링하는 클래스이다.
 * 최근 수정 일자 : 2024.05.29(수)
 */
package com.pathfind.system.controller;

import com.pathfind.system.domain.Member;
import com.pathfind.system.findPathService2Domain.FindPathRoom;
import com.pathfind.system.findPathService2Domain.UserInfo;
import com.pathfind.system.findPathService2Dto.*;
import com.pathfind.system.notificationServiceDomain.NotificationType;
import com.pathfind.system.service.FindPathRoomService;
import com.pathfind.system.service.MemberService;
import com.pathfind.system.service.NotificationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

@Controller
@RequiredArgsConstructor
@RequestMapping(value = "/service2/*")
public class FindPathRoomController {

    private static final Logger logger = LoggerFactory.getLogger(FindPathRoomController.class);

    private final FindPathRoomService findPathRoomService;
    private final NotificationService notificationService;
    private final MemberService memberService;

    // service2 메인 화면
    @GetMapping("/enter")
    public String enterService2(HttpServletRequest request, RedirectAttributes rttr) {
        logger.info("Service2 처음 페이지 입장");
        HttpSession session = request.getSession(false);
        if (session == null) {
            rttr.addFlashAttribute("message", "사람간 길찾기 서비스 이용을 하시려면 로그인을 진행해 주세요.");
            return "redirect:/";
        }
        Member loginMember = (Member) session.getAttribute(SessionConst.LOGIN_MEMBER);
        session.setAttribute(SessionConst.SUBMIT_MEMBER, null);

        //세션에 회원 데이터가 없으면 home
        if (loginMember == null) {
            logger.info("로그인을 진행하지 않았을 때");
            rttr.addFlashAttribute("message", "사람간 길찾기 서비스 이용을 하시려면 로그인을 진행해 주세요.");
            return "redirect:/";
        }

        //model.addAttribute("CreateRoomVCRequest", new CreateRoomVCRequest());
        //정상적으로 방을 생성하였음(방이름, 이동수단을 매개변수)
        //logger.info("loginMember: {}", loginMember.getNickname());

        return "service2/service2Home";
    }

    //채팅방 개설
    @ResponseBody
    @PostMapping(value = "/create-room")
    public String createRoom(@ModelAttribute(value = "CreateRoomVCRequest") @Valid CreateRoomVCRequest form, HttpServletRequest request, HttpServletResponse response) throws IOException {
        logger.info("Create service2 room , name: {}", form.getRoomName());
        HttpSession session = request.getSession(false);
        String path = request.getHeader("REFERER").substring(0, request.getHeader("REFERER").indexOf("/service2"));
        //logger.info("URL: {}", path);
        if (session == null) {
            response.sendError(400, "사람간 길찾기 서비스 이용을 하시려면 로그인을 진행해 주세요.");
            return path;
        }
        Member loginMember = (Member) Objects.requireNonNull(session).getAttribute(SessionConst.LOGIN_MEMBER);

        //세션에 회원 데이터가 없으면 home
        if (loginMember == null) {
            logger.info("로그인 상태가 아니었을 때 Service2를 사용하려고 시도하였음.");
            response.sendError(400, "사람간 길찾기 서비스 이용을 하시려면 로그인을 진행해 주세요.");
            return path;
        }

        FindPathRoom newRoom = findPathRoomService.createRoom(loginMember.getUserId(), loginMember.getNickname(), form.getRoomName(), form.getTransportationType());
        //loginMember가 방장이 되어 그 방의 초대 리스트에 들어가게 된다
        //logger.info("go to: {}", path + "/service2/room?roomId=" + newRoom.getRoomId());
        return path + "/service2/room?roomId=" + newRoom.getRoomId();
    }

    //채팅방 입장
    @GetMapping("/room")
    public String getRoom(@RequestParam(value = "roomId") String roomId, Model model, HttpServletRequest request, RedirectAttributes rttr) throws IOException {
        logger.info("get service2 room, roomId : {}", roomId);
        //logger.info("room: {}", findPathRoomService.findRoomById(roomId));
        HttpSession session = request.getSession(false);
        if (session == null) {
            rttr.addFlashAttribute("message", "사람간 길찾기 서비스 이용을 하시려면 로그인을 진행해 주세요.");
            return "redirect:/";
        }

        Member loginMember = (Member) session.getAttribute(SessionConst.LOGIN_MEMBER);
        session.setAttribute(SessionConst.SUBMIT_MEMBER, null);

        //세션에 회원 데이터가 없으면 redirect:/
        if (loginMember == null) {
            rttr.addFlashAttribute("message", "사람간 길찾기 서비스 이용을 하시려면 로그인을 진행해 주세요.");
            return "redirect:/";
        }

        FindPathRoom room = findPathRoomService.findRoomById(roomId);

        // roomId에 해당하는 방이 없다면 redirect:/
        if (room == null) {
            logger.info("{}라는 방이 없음", roomId);
            rttr.addFlashAttribute("message", "방 아이디 '" + roomId + "'에 해당하는 방이 존재하지 않습니다.");
            return "redirect:/";
        }

        //길찾기 방에 회원에 초대받지 않았다면 redirect:/
        if (!room.checkMemberInvited(loginMember.getUserId())) {
            logger.info("{}가 길찾기방에 초대되지 않아서 입장에 실패하였음", loginMember.getNickname());
            rttr.addFlashAttribute("message", "방 이름 '" + room.getRoomName() + "'에 해당하는 방에 초대받지 못했습니다.");
            return "redirect:/";
        }

        notificationService.deleteNotificationByRoomIdAndUserId(room.getRoomId(), loginMember.getUserId());
        model.addAttribute("room", room);

        return "service2/room";
    }

    // 채팅방 초대
    @ResponseBody
    @GetMapping("/room/invite")
    public InviteMemberVCResponse invite(@Valid InviteMemberVCRequest form, HttpServletRequest request) throws IOException {
        String roomId = form.getRoomId();
        String nickname = form.getNickname();
        logger.info("Invite {} at room, roomId: {}", nickname, roomId);
        Member member = Member.createMember(null, null, nickname, null, null);
        List<Member> memberList = memberService.findByNickname(member);

        // nickname이 데이터베이스에 존재하는 것인지 여부를 확인한다.
        if (memberList.isEmpty()) {
            logger.info("{} isn't exist at DB", nickname);
            return new InviteMemberVCResponse(InviteType.NOT_INVITED, "'" + nickname + "'은 존재하지 않는 닉네임 입니다.");
        }

        String userId = memberList.get(0).getUserId();

        // 이미 roomId에 해당하는 길찾기 방에 초대가 되어 있는지 여부를 확인한다.
        if (findPathRoomService.checkMemberInvited(roomId, userId)) {
            logger.info("{} is already invited at room, roomId {}", roomId, nickname);
            return new InviteMemberVCResponse(InviteType.DUPLICATE_INVITE, "'" + nickname + "'님은 이미 초대되었습니다.");
        }

        if (findPathRoomService.checkMemberCur(roomId, userId) && findPathRoomService.findRoomById(roomId).getOwnerUserId().equals(userId)) {
            logger.info("{} is already connected at room, roomId {}", roomId, nickname);
            return new InviteMemberVCResponse(InviteType.SELF_INVITED, "자기 자신을 초대할 수 없습니다.");
        }

        // 이미 roomId에 해당하는 길찾기 방에 접속해 있는지 여부를 확인한다.
        if (findPathRoomService.checkMemberCur(roomId, userId)) {
            logger.info("{} is already invited at room, roomId {}", roomId, nickname);
            return new InviteMemberVCResponse(InviteType.ALREADY_CONNECTED, "'" + nickname + "'님은 이미 방에 접속해 있습니다.");
        }

        FindPathRoom room = findPathRoomService.inviteMember(roomId, userId, nickname);
        if (!room.getOwnerUserId().equals(userId)) {
            String path = request.getHeader("REFERER");
            logger.info("path: {}", path);
            notificationService.sendInviteNotification(room.getOwnerNickname() + "님이 " + room.getRoomName() + "방으로 회원님을 초대했습니다.",
                    room.getOwnerUserId(),
                    userId,
                    NotificationType.INVITE,
                    path,
                    roomId);
        }
        logger.info("{} is invited at room successfully, roomId: {}", nickname, roomId);

        return new InviteMemberVCResponse(InviteType.INVITED, "'" + nickname + "'님이 " + room.getRoomName() + "방에 초대되었습니다.");
    }

    // 채팅방 퇴장
    @GetMapping("/room/leave")
    public String leaveRoom(@RequestParam(value = "roomName") String roomName, @RequestParam(value = "reason") String reason, RedirectAttributes rttr) {
        logger.info("Leave room, roomName: {}", roomName);
        rttr.addFlashAttribute("message", reason);
        return "redirect:/";
    }

    @GetMapping("/room/curUserlist")
    @ResponseBody
    public List<UserInfoVCResponse> curUserlist(@RequestParam(value = "roomId") String roomId) throws IOException {
        if (findPathRoomService.findRoomById(roomId) == null) return null;
        logger.info("현재 roomId {}에 있는 모든 user를 보여주기", roomId);

        return findPathRoomService.getCurRoomList(roomId).stream().map(m -> new UserInfoVCResponse(m.getUserId(), m.getNickname())).toList();
    }

    @GetMapping("/room/inviteUserlist")
    @ResponseBody
    public List<String> inviteUserlist(@RequestParam(value = "roomId") String roomId) throws IOException {
        if (findPathRoomService.findRoomById(roomId) == null) return null;
        //logger.info("roomId {}에 초대된 user를 보여주기", roomId);

        return findPathRoomService.getRoomInviteList(roomId);
    }
}
