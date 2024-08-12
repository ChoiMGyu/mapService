/*
 * 클래스 기능 : 비밀번호 변경을 수행하기 위한 form
<<<<<<< Updated upstream
 * 최근 수정 일자 : 2024.01.17(수)
=======
 * 최근 수정 일자 : 2024.01.20(토)
>>>>>>> Stashed changes
 */
package com.pathfind.system.memberDto;

import com.pathfind.system.validation.ValidationGroups;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.hibernate.validator.constraints.Length;

@Data
public class PasswordForm {

    @NotEmpty(message = "기존 비밀번호 입력은 필수입니다", groups = ValidationGroups.NotEmptyGroup.class)
    @Length(min = 8, max = 20, groups = ValidationGroups.LengthCheckGroup.class)
    private String oldPassword;

    @NotEmpty(message = "새로운 패스워드 입력은 필수입니다", groups = ValidationGroups.NotEmptyGroup.class)
    @Length(min = 8, max = 20, groups = ValidationGroups.LengthCheckGroup.class)
    private String newPassword1;

    @NotEmpty(message = "새로운 패스워드 확인 입력은 필수입니다", groups = ValidationGroups.NotEmptyGroup.class)
    @Length(min = 8, max = 20, groups = ValidationGroups.LengthCheckGroup.class)
    private String newPassword2;
}
