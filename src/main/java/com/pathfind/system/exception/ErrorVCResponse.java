/*
 * 클래스 기능 : 클라이언트에게 예외를 반환할 때 사용하는 error dto 클래스
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.exception;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ErrorVCResponse {
    private String field;
    private String code;
    private String message;
}
