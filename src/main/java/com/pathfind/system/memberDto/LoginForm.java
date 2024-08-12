/*
 * 클래스 기능 : 로그인을 수행하기 위해 클라이언트로부터 컨트롤러로 넘겨주는 form
 * 최근 수정 일자 : 2024.01.15(월)
 */
package com.pathfind.system.memberDto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class LoginForm {

    //@Column(length = 12, nullable = false, unique = true)
    @NotEmpty(message = "아이디 입력은 필수입니다")
    private String userId; //아이디

    //@Column(length = 20, nullable = false)
    @NotEmpty(message = "비밀번호 입력은 필수입니다")
    private String password; //비밀번호 // 변경 가능
}
