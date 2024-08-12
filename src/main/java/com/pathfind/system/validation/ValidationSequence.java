/*
 * 클래스 기능 : Validation 그룹의 순서를 지정하는 인터페이스
 * 최근 수정 일자 : 2024.08.02(금)
 */
package com.pathfind.system.validation;

import jakarta.validation.GroupSequence;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.groups.Default;

import static com.pathfind.system.validation.ValidationGroups.*;

@GroupSequence({NotEmptyGroup.class, PatternGroup.class, LengthCheckGroup.class})
public interface ValidationSequence {
}
