/*
 * 클래스 기능 : 실시간 상대방 길 찾기 서비스(서비스2) 인터페이스
 * 최근 수정 일자 : 2024.05.29(수)
 */
package com.pathfind.system.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.pathfind.system.findPathService2Domain.*;
import com.pathfind.system.findPathService2Domain.FindPathRoom;
import com.pathfind.system.findPathService2Domain.MemberLatLng;
import com.pathfind.system.findPathService2Domain.TransportationType;
import com.pathfind.system.findPathService2Dto.ShortestPathRouteCSResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public interface FindPathRoomService {
    public List<FindPathRoom> findAllRoom();

    public FindPathRoom findRoomById(String roomId) throws IOException;

    public List<RoomMemberInfo> getCurRoomList(String roomId) throws IOException;

    public List<String> getRoomInviteList(String roomId) throws IOException;

    public ArrayList<String> deleteListUser(String roomId, String userId) throws IOException;

    public void changeOwnerUserId(String roomId, String userId) throws IOException;

    public FindPathRoom createRoom(String userId, String nickname, String roomName, TransportationType transportationType) throws JsonProcessingException;

    public FindPathRoom changeRoomMemberLocation(String roomId, String sender, MemberLatLng memberLatLng) throws IOException;

    public List<ShortestPathRouteCSResponse> findShortestRoute(FindPathRoom findPathRoom);

    public void deleteRoom(String roomId);

    public FindPathRoom inviteMember(String roomId, String userId, String nickname) throws IOException;

    public boolean checkMemberInvited(String roomId, String userId) throws IOException;

    public boolean checkMemberCur(String roomId, String userId) throws IOException;

    public FindPathRoom memberEnterRoom(String roomId, String userId, String nickname) throws IOException;

    public FindPathRoom leaveRoom(String userId) throws IOException;

    public FindPathRoom leaveRoom(String userId, String roomId) throws IOException;

    public FindPathRoom findCurRoomByUserId(String userId);
}
