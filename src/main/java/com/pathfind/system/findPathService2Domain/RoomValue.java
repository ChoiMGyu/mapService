/*
 * 클래스 기능 : 방 아이디의 길이 등을 정의한 클래스이다.
 * 최근 수정 일자 : 2024.03.18(월)
 */
package com.pathfind.system.findPathService2Domain;

import java.time.LocalDateTime;

public abstract class RoomValue {
    public static final int ROOM_ID_LENGTH = 10;
    public static final int ROOM_MAX_MEMBER_NUM = 5;
    public static final long ROOM_DELETION_TIME = 5;
    public static final LocalDateTime ROOM_DELETE_CANCEL = LocalDateTime.MAX;

    public static final long ROOM_DURATION = 60 * 60 * 2;

    public static final double NAVIGATION_STOPPING_DISTANCE = 30.0;
}
