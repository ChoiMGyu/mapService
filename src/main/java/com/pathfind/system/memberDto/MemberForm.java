/*
 * 클래스 기능 : 회원 정보를 클라이언트와 컨트롤러 사이에서 주고받기 위해 사용되는 form이다.
 * 최근 수정 일자 : 2024.01.22(월)
 */
package com.pathfind.system.memberDto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class MemberForm {

    @NotEmpty(message = "아이디는 필수입니다.")
    //@Pattern(regexp = "(?=.*[0-9])(?=.*[a-zA-Z]).{5,12}", message = "아이디는 5~12자 영문 대 소문자, 숫자를 사용하세요.")
    private String userId; //아이디

    @NotEmpty(message = "비밀번호는 필수입니다.")
    //@Pattern(regexp = "(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,20}", message = "비밀번호는 8~20자 영문 대 소문자, 숫자, 특수문자를 사용하세요.")
    private String password; //비밀번호

    @NotEmpty(message = "닉네임은 필수입니다.")
    //@Pattern(regexp = "^[ㄱ-ㅎ가-힣a-zA-Z0-9-_]{2,10}$", message = "닉네임은 특수문자를 제외한 2~12자리여야 합니다.")
    private String nickname; //닉네임

    @NotEmpty(message = "이메일은 필수입니다.")
    //@Pattern(regexp = "^(?:\\w+\\.?)*\\w+@(?:\\w+\\.)+\\w+$", message = "이메일 형식이 올바르지 않습니다.")
    private String email; //이메일
}
