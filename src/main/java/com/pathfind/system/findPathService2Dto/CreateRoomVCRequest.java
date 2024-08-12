/*
 * 클래스 기능 : 방 생성 요청 시 사용되는 dto이다.
 * 최근 수정 일자 : 2024.04.06(월)
 */
package com.pathfind.system.findPathService2Dto;

import com.pathfind.system.findPathService2Domain.TransportationType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import lombok.Getter;

@Data
public class CreateRoomVCRequest {
    @Pattern(regexp = "^[ㄱ-ㅎ가-힣a-zA-Z0-9-_\\s]{2,30}$", message = "방 이름은 특수문자를 제외한 2~30자리여야 합니다.")
    private String roomName; //방 이름

    @NotNull
    private TransportationType transportationType; //도보 or 자동차

    //roomName은 방 만들기에 사용이 되지만 transportaionType은 RoomMemberInfo에 사용이 되므로
    //분리가 필요하지 않을까, 오히려 CreateRoomVC에는 nickname이 전달되어야 할 것이다
}
