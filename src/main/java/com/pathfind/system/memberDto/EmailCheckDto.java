/*
 * 클래스 기능 : 사용자의 이메일과 사용자의 입력 인증번호를 받아오는 DTO
 * 최근 수정 일자 : 2024.01.10(수)
 */
package com.pathfind.system.memberDto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class EmailCheckDto {
    //이메일 인증 확인을 위한 정보를 가져오는 DTO
    //API 설계에서는 Entity를 Controller에서 노출하면 안됨
    @Email
    @NotEmpty(message = "이메일을 입력해 주세요")
    private String email; //인증 이메일

    @NotEmpty(message = "인증 번호를 입력해 주세요")
    private String authNum; //입력받은 인증번호
}
