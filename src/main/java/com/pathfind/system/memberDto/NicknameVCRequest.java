/*
 * 클래스 기능 : 사용자로부터 받은 닉네임 유효성 검증을 위해 사용되는 dto 클래스
 * 최근 수정 일자 : 2024.08.02(금)
 */
package com.pathfind.system.memberDto;

import com.pathfind.system.validation.ValidationGroups;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import static com.pathfind.system.validation.ValidationGroups.*;

@Schema(name = "NicknameVCRequest", description = "유저 닉네임 유효성 검증에 쓰이는 dto")
@Data
public class NicknameVCRequest {
    @Schema(name = "nickname", description = "유저 닉네임", example = "qwer1234")
    @NotEmpty(message = "닉네임은 필수입니다.", groups = NotEmptyGroup.class)
    @Pattern(regexp = "^[ㄱ-ㅎ가-힣a-zA-Z0-9-_\\s]{2,12}$", message = "닉네임은 특수문자를 제외한 2~12자리여야 합니다.", groups = PatternGroup.class)
    private String nickname; // 닉네임
}
