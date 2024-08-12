/*
 * 클래스 기능 : 실시간 상대방 길 찾기 서비스(서비스2)에서 길 찾기 방에 초대된 인원의 속성을 정의한 클래스이다.
 * 최근 수정 일자 : 2024.05.29(수)
 */
package com.pathfind.system.findPathService2Domain;

import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter(AccessLevel.PROTECTED)
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RoomMemberInfo {
    private String userId;
    private String nickname;
    private RoomMemberType roomMemberType;
    private MemberLatLng location;
    private Long closestVertexId;
    private LocalDateTime roomExitTime;

    public RoomMemberInfo(String userId, String nickname, RoomMemberType roomMemberType, MemberLatLng location, Long closestVertexId) {
        this.userId = userId;
        this.nickname = nickname;
        this.roomMemberType = roomMemberType;
        this.location = location;
        this.closestVertexId = closestVertexId;
        this.roomExitTime = RoomMemberValue.ROOM_EXIT_CANCEL;
    }

    public void changeLocation(MemberLatLng loc) {
        if (location == null) {
            setLocation(loc);
        }
        if (location.equals(loc)) {
            if (roomExitTime.isEqual(RoomMemberValue.ROOM_EXIT_CANCEL)) {
                setRoomExitTime(LocalDateTime.now().plusMinutes(RoomMemberValue.ROOM_EXIT_TIME));
            }
        } else {
            setLocation(loc);
            if (!roomExitTime.isEqual(RoomMemberValue.ROOM_EXIT_CANCEL)) {
                setRoomExitTime(RoomMemberValue.ROOM_EXIT_CANCEL);
            }
        }
    }
}
