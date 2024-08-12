/*
 * 클래스 기능 : 실시간 상대방 길 찾기 서비스(서비스2) 구현체
 * 최근 수정 일자 : 2024.05.29(수)
 */
package com.pathfind.system.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pathfind.system.algorithm.Dijkstra;
import com.pathfind.system.algorithm.Graph;
import com.pathfind.system.algorithm.Node;
import com.pathfind.system.domain.*;
import com.pathfind.system.domain.Objects;
import com.pathfind.system.findPathDto.VertexInfo;
import com.pathfind.system.findPathService2Domain.*;
import com.pathfind.system.findPathService2Dto.ShortestPathRouteCSResponse;
import com.pathfind.system.findPathService2Domain.UserInfo;
import com.pathfind.system.repository.RoadEdgeRepository;
import com.pathfind.system.repository.RoadVertexRepository;
import com.pathfind.system.repository.SidewalkEdgeRepository;
import com.pathfind.system.repository.SidewalkVertexRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.*;

@Service
@RequiredArgsConstructor
@Transactional
public class FindPathRoomServiceImpl implements FindPathRoomService {

    private static final Logger logger = LoggerFactory.getLogger(FindPathRoomServiceImpl.class);

    private final RedisUtil redisUtil;
    private final ObjectMapper objectMapper;
    private final RoadEdgeRepository roadEdgeRepository;
    private final RoadVertexRepository roadVertexRepository;
    private final SidewalkEdgeRepository sidewalkEdgeRepository;
    private final SidewalkVertexRepository sidewalkVertexRepository;
    private final NotificationService notificationService;

    @Override
    public List<FindPathRoom> findAllRoom() {
        logger.info("Get all room");
        ListOperations<String, String> allData = redisUtil.getAllDataList();
        Set<String> keys = allData.getOperations().keys("*");
        if (keys == null) return null;
        List<FindPathRoom> rooms = new ArrayList<>();
        for (String key : keys) {
            if (key.length() != RoomValue.ROOM_ID_LENGTH) continue;
            try {
                String data = null;
                data = allData.index(key, 0);
                rooms.add(objectMapper.readValue(data, FindPathRoom.class));
            } catch (JsonProcessingException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("All room data: ");
        for (FindPathRoom room : rooms) {
            logger.info("{}", room);
        }
        return rooms;
    }

    @Override
    public FindPathRoom findRoomById(String roomId) throws IOException {
        logger.info("Get room, roomId: {}", roomId);
        String jsonStringRoom = redisUtil.getDataList(roomId);
        return jsonStringRoom == null ? null : objectMapper.readValue(jsonStringRoom, FindPathRoom.class);
    }

    @Override
    public List<RoomMemberInfo> getCurRoomList(String roomId) throws IOException {
        //logger.info("roomId {}에 있는 현재 유저들의 리스트 반환", roomId);

        FindPathRoom findPathRoom = findRoomById(roomId);

        RoomMemberInfo owner = findPathRoom.getOwner();
        findPathRoom.getCurMember().remove(owner);
        findPathRoom.getCurMember().add(0, owner);

        return findPathRoom.getCurMember();
    }

    @Override
    public List<String> getRoomInviteList(String roomId) throws IOException {
        //logger.info("roomId {}에 있는 초대 유저들의 리스트 반환", roomId);

        FindPathRoom findPathRoom = findRoomById(roomId);
        //logger.info("getRoomInviteList 객체 : " + findPathRoom);

        return findPathRoom.getInvitedMember().stream().map(UserInfo::getNickname).toList();
    }

    @Override
    public ArrayList<String> deleteListUser(String roomId, String userId) throws IOException {
        logger.info("roomId {}에 있는 userId {}인 유저를 현재 인원에서 삭제", roomId, userId);

        FindPathRoom findPathRoom = findRoomById(roomId);

        //logger.info("deleteListUser 객체 : " + findPathRoom);

        findPathRoom.leaveRoomCurMember(userId);

        String jsonStringRoom = objectMapper.writeValueAsString(findPathRoom);
        redisUtil.setDataList(roomId, jsonStringRoom);

        ArrayList<String> result = new ArrayList<>();
        for (int i = 0; i < findPathRoom.getCurMember().size(); i++) {
            result.add(findPathRoom.getCurMember().get(i).getNickname());
        }

        return result;
    }

    @Override
    public void changeOwnerUserId(String roomId, String userId) throws IOException {
        FindPathRoom findPathRoom = findRoomById(roomId);

        logger.info("roomId {}의 방장을 {}에서 {}로 교체", roomId, findPathRoom.getOwnerUserId(), userId);

        //RoomMemberInfo lastOwner = findPathRoom.findMemberByNickname(findPathRoom.getOwnerName());
        //findPathRoom.getCurMember().remove(0);
        findPathRoom.changeOwnerUserId(userId);
        //findPathRoom.getCurMember().add(lastOwner);

        String jsonStringRoom = objectMapper.writeValueAsString(findPathRoom);
        redisUtil.setDataList(roomId, jsonStringRoom);
    }

    @Override
    public FindPathRoom createRoom(String userId, String nickname, String roomName, TransportationType transportationType) throws JsonProcessingException {
        logger.info("Create room...");
        FindPathRoom findPathRoom = FindPathRoom.createFindPathRoom(roomName, transportationType);
        while (redisUtil.getDataList(findPathRoom.getRoomId()) != null) findPathRoom.createRoomId();
        pushManagerInvited(findPathRoom, userId, nickname);

        String jsonStringRoom = objectMapper.writeValueAsString(findPathRoom);
        logger.info("Create jsonStringRoom: {}", jsonStringRoom);

        redisUtil.setDataExpireList(findPathRoom.getRoomId(), jsonStringRoom, RoomValue.ROOM_DURATION);
        return findPathRoom;
    }

    public void pushManagerInvited(FindPathRoom room, String userId, String nickname) {
        room.pushNewMember(userId, nickname);
        room.changeOwnerUserId(userId);
    }

    @Override
    public FindPathRoom changeRoomMemberLocation(String roomId, String sender, MemberLatLng memberLatLng) throws IOException {
        //logger.info("Change room member's location, roomId {}", roomId);
        FindPathRoom room = findRoomById(roomId);
        if (room == null) return null;

        room.changeMemberLocation(sender, memberLatLng);
        double memberLat = memberLatLng.getLatitude(), memberLng = memberLatLng.getLongitude(), dist = 1000000.0;

        //logger.info("Member({})'s current location - latitude: {}, longitude: {}", sender, memberLat, memberLng);
        //logger.info("Find closest vertexId...");
        List<? extends BasicVertex> vertices;
        if (room.getTransportationType() == TransportationType.ROAD) {
            vertices = roadVertexRepository.findAll();
        } else {
            vertices = sidewalkVertexRepository.findAll();
        }

        for (BasicVertex vertex : vertices) {
            Objects object = vertex.getObject();
            boolean isInfoVertex = object != null && (object.getObjectType() == ObjType.BUILDING || object.getObjectType() == ObjType.LANDMARK);
            if (isInfoVertex) continue;
            double tmpDist = Math.pow(Math.abs(memberLat - vertex.getLatitude()), 2) + Math.pow(Math.abs(memberLng - vertex.getLongitude()), 2);
            if (dist > tmpDist) {
                //logger.info("VertexId: {}, distance difference: {}, minimum distance: {}", vertex.getId() - 1, tmpDist, dist);
                dist = tmpDist;
                room.changeMemberClosestVertexId(sender, vertex.getId() - 1);
            }
        }
        //logger.info("Member({})'s closest vertexId: {}", sender, room.findMemberByNickname(sender).getClosestVertexId());
        String jsonStringRoom = objectMapper.writeValueAsString(room);
        redisUtil.setDataList(roomId, jsonStringRoom);
        return room;
    }

    /**
     * 멤버 m의 위치에서 정점 s, e을 지나는 직선으로 수선을 내렸을 때의 교점을 구하는 함수이다.
     * 이차원 평면에 있다고 가정하고 교점을 구했지만 경도, 위도는 지구의 좌표 표현 방법이므로 이차원 평면 상에 구한 교점은 실제 교점과 오차가 존재한다.
     */
    public VertexInfo getInterSectionPoint(MemberLatLng m, double sLat, double sLng, double eLat, double eLng) {
        double gradient = (sLat - eLat) / (sLng - eLng), yIntercept = gradient * -1 * sLng + sLat;
        double gradient2 = -1 / gradient, yIntercept2 = gradient2 * -1 * m.getLongitude() + m.getLatitude();
        double lng = (yIntercept - yIntercept2) / (gradient2 - gradient);
        double lat = gradient * lng + yIntercept;
        return new VertexInfo(lat, lng);
    }

    /**
     * 길 찾기 경로의 시작, 끝 부분을 보정, 개선하는 함수이다. 경로를 자연스럽게 다듬는다.
     */
    public List<VertexInfo> improveRoute(int startVertex, int endVertex, MemberLatLng memberLatLng, List<VertexInfo> routeInfo) {
        if (routeInfo.size() < 3) { // routeInfo의 정점이 세 개 이상일때 실행한다. 길 찾기 경로를 자연스럽게 만들기 위해 사용된다.
            return routeInfo;
        }

        VertexInfo v1 = routeInfo.get(startVertex), v2 = routeInfo.get(endVertex);
        double v1Lat = v1.getLatitude(), v1Lng = v1.getLongitude();
        double v2Lat = v2.getLatitude(), v2Lng = v2.getLongitude();
        double tmpSLat = v1Lat, tmpSLng = v1Lng;
        if (v1Lat > v2Lat) {
            v1Lat = v2Lat;
            v2Lat = tmpSLat;
        }
        if (v1Lng > v2Lng) {
            v1Lng = v2Lng;
            v2Lng = tmpSLng;
        }

        VertexInfo startIntersectionPoint = getInterSectionPoint(memberLatLng, v1Lat, v1Lng, v2Lat, v2Lng);
        double sLat = startIntersectionPoint.getLatitude(), sLng = startIntersectionPoint.getLongitude();

        /*
         * 방장의 위치에서 ((startVertex)번 정점-> (endVertex)번 정점)간선으로 수선을 내렸을 때
         * 간선 안에 교점이 존재한다면 교점과 (endVertex)번 정점 중간의 점의 위치로 (startVertex)번 정점을 교체한다.
         **/
        if (v1Lat < sLat && sLat < v2Lat && v1Lng < sLng && sLng < v2Lng) {
            v2Lat = v2.getLatitude();
            v2Lng = v2.getLongitude();
            //logger.info("new sLat: {}, sLng: {}", (sLat + s2Lat) / 2, (sLng + s2Lng) / 2);
            routeInfo.set(startVertex, new VertexInfo((sLat + v2Lat) / 2, (sLng + v2Lng) / 2));
        }

        if (routeInfo.size() == 3) {
            routeInfo.remove(1);
        }

        return routeInfo;
    }

    @Override
    public List<ShortestPathRouteCSResponse> findShortestRoute(FindPathRoom findPathRoom) {
        MemberLatLng ownerLatLng = findPathRoom.getOwner().getLocation();
        List<? extends BasicVertex> vertices;
        List<? extends BasicEdge> edges;
        //FindPathFactory<V, E> findPathFactory;
        if (findPathRoom.getTransportationType() == TransportationType.ROAD) {
            vertices = roadVertexRepository.findAll();
            edges = roadEdgeRepository.findAll();
        } else {
            vertices = sidewalkVertexRepository.findAll();
            edges = sidewalkEdgeRepository.findAll();
        }

        //logger.info("RoadVertices size: {}", numVertices);

        int numVertices = vertices.size();
        Graph graph = new Graph(numVertices);
        Long start = findPathRoom.getOwner().getClosestVertexId();
        //logger.info("RoadEdges size: {}", edges.size());
        for (BasicEdge edge : edges) {
            //logger.info("Edge 정보 : " + edge.getRoadVertex1() + " " + edge.getRoadVertex2() + " " + edge.getLength());
            Objects object = vertices.get(Math.toIntExact(edge.getVertex2() - 1)).getObject();
            boolean isInfoVertex = object != null && (object.getObjectType() == ObjType.BUILDING || object.getObjectType() == ObjType.LANDMARK);
            graph.addEdge(edge.getVertex1() - 1, edge.getVertex2() - 1, edge.getLength(), isInfoVertex);
        }
        List<Node> nodes = new ArrayList<>();
        for (BasicVertex vertex : vertices) {
            Objects object = vertex.getObject();
            boolean isInfoVertex = object != null && (object.getObjectType() == ObjType.BUILDING || object.getObjectType() == ObjType.LANDMARK);
            nodes.add(new Node(vertex.getId() - 1, 0, isInfoVertex));
        }

        Dijkstra getRoute = new Dijkstra();
        getRoute.dijkstra(nodes, graph, start, -1L);
        List<ShortestPathRouteCSResponse> result = new LinkedList<>();
        //logger.info("방장과 각 인원들의 경로 계산");
        String ownerNickname = findPathRoom.getOwnerNickname();
        for (int i = 0; i < findPathRoom.getCurMember().size(); i++) {
            RoomMemberInfo member = findPathRoom.getCurMember().get(i);
            if (ownerNickname.equals(member.getNickname())) continue;
            Long end = member.getClosestVertexId();
            if (end == null) continue;
            //logger.info("방장, {}번째 사람의 경로", end);
            MemberLatLng memberLatLng = member.getLocation();
            List<VertexInfo> routeInfo = new ArrayList<>();
            //logger.info("시작 위치 - latitude: {}, longitude: {}", startLatLng.getLatitude(), startLatLng.getLongitude());
            List<Integer> shortestRoute = getRoute.getShortestRoute(start, end);
            //logger.info("끝 위치 - latitude: {}, longitude: {}", memberLatLng.getLatitude(), memberLatLng.getLongitude());

            routeInfo.add(new VertexInfo(ownerLatLng.getLatitude(), ownerLatLng.getLongitude())); // 방장의 위치
            for (Integer idx : shortestRoute) { // 방장과 가장 가까운 정점, 회원(i)와 가장 가까운 정점 사이의 경로
                routeInfo.add(new VertexInfo(vertices.get(idx).getLatitude(), vertices.get(idx).getLongitude()));
            }
            routeInfo.add(new VertexInfo(memberLatLng.getLatitude(), memberLatLng.getLongitude())); // 회원(i)의 위치

            routeInfo = improveRoute(1, 2, ownerLatLng, routeInfo);
            routeInfo = improveRoute(routeInfo.size() - 2, routeInfo.size() - 3, memberLatLng, routeInfo);

            result.add(new ShortestPathRouteCSResponse(member.getNickname(), getTotalDistance(routeInfo), routeInfo));
        }

        return result;
    }

    /**
     * 방장과 회원까지의 최종 거리를 계산하는 함수이다.
     */
    private double getTotalDistance(List<VertexInfo> routes) {
        double totalDistance = 0.0;
        for (int i = 1; i < routes.size(); i++) {
            totalDistance += findAdditionalDistance(routes.get(i - 1), routes.get(i));
        }

        logger.warn("Total distance: {}", totalDistance);

        return totalDistance;
    }

    /**
     * 위도 경도로 표현되는 두 정점 사이의 거리를 미터 단위로 구하는 함수이다.
     */
    private double findAdditionalDistance(VertexInfo s, VertexInfo e) {
        double sLat = s.getLatitude(), sLng = s.getLongitude();
        double sLatRad = sLat * Math.PI / 180.0, sLngRad = sLng * Math.PI / 180.0;

        double eLat = e.getLatitude(), eLng = e.getLongitude();
        double eLatRad = eLat * Math.PI / 180.0, eLngRad = eLng * Math.PI / 180.0;

        double theta = (sLng - eLng) * Math.PI / 180.0;

        double additionalDistance;
        additionalDistance = Math.sin(sLatRad) * Math.sin(eLatRad) + Math.cos(sLatRad) * Math.cos(eLatRad) * Math.cos(theta);
        additionalDistance = Math.acos(additionalDistance);
        additionalDistance *= 180.0 / Math.PI;
        additionalDistance *= 60 * 1.1515 * 1609.344;

        return additionalDistance;
    }

    @Override
    public void deleteRoom(String roomId) {
        logger.info("Delete room, id: {}", roomId);
        notificationService.deleteAllNotificationByRoomId(roomId);
        redisUtil.deleteData(roomId);
    }

    @Override
    public FindPathRoom inviteMember(String roomId, String userId, String nickname) throws IOException {
        logger.info("Invite member {} to room, roomId: {}", userId, roomId);
        FindPathRoom room = findRoomById(roomId);
        room.pushNewMember(userId, nickname);
        String jsonStringRoom = objectMapper.writeValueAsString(room);
        redisUtil.setDataList(roomId, jsonStringRoom);
        return room;
    }

    @Override
    public boolean checkMemberInvited(String roomId, String userId) throws IOException {
        logger.info("Check {} is already invited at roomId {}", userId, roomId);
        FindPathRoom room = findRoomById(roomId);
        return room.checkMemberInvited(userId);
    }

    @Override
    public boolean checkMemberCur(String roomId, String userId) throws IOException {
        logger.info("Check {} is already connect at roomId {}", userId, roomId);
        FindPathRoom room = findRoomById(roomId);
        return room.checkMemberCur(userId);
    }

    @Override
    public FindPathRoom memberEnterRoom(String roomId, String userId, String nickname) throws IOException {
        logger.info("{} enter the room, roomId: {}", nickname, roomId);
        FindPathRoom room = findRoomById(roomId);
        if (room == null) return null;
        room.enterRoom(userId, nickname, room.getOwnerUserId().equals(userId) ? RoomMemberType.OWNER : RoomMemberType.NORMAL, null, null);
        String jsonStringRoom = objectMapper.writeValueAsString(room);
        redisUtil.setDataList(room.getRoomId(), jsonStringRoom);

        return room;
    }

    @Override
    public FindPathRoom leaveRoom(String userId) throws IOException {
        FindPathRoom room = findCurRoomByUserId(userId);
        if (room == null) return null;
        String roomId = room.getRoomId();
        RoomMemberInfo member = room.findMemberByUserId(userId);
        logger.info("{} leaves the room, roomId: {}", member.getNickname(), roomId);
        room.leaveRoomCurMember(userId);
        String jsonStringRoom = objectMapper.writeValueAsString(room);
        redisUtil.setDataList(roomId, jsonStringRoom);
        return room;
    }

    @Override
    public FindPathRoom leaveRoom(String userId, String roomId) throws IOException {
        FindPathRoom room = findRoomById(roomId);
        if (room == null || !room.checkMemberCur(userId)) return null;
        RoomMemberInfo member = room.findMemberByUserId(userId);
        logger.info("{} leaves the room, roomId: {}", member.getNickname(), roomId);
        room.leaveRoomCurMember(userId);
        String jsonStringRoom = objectMapper.writeValueAsString(room);
        redisUtil.setDataList(roomId, jsonStringRoom);
        return room;
    }

    @Override
    public FindPathRoom findCurRoomByUserId(String userId) {
        logger.info("Find room by nickname");
        List<FindPathRoom> rooms = findAllRoom();
        FindPathRoom result = null;
        for (FindPathRoom room : rooms) {
            if (room.checkMemberCur(userId)) {
                result = room;
                break;
            }
        }
        return result;
    }
}
