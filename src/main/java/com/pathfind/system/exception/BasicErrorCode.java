/*
 * 클래스 기능 : 기본 에러 코드 인터페이스
 * 최근 수정 일자 : 2024.07.20(토)
 */
package com.pathfind.system.exception;

public interface BasicErrorCode {
    public ErrorReason getErrorReason();
    public String getCode();
    public String getDescription();
    public ErrorVCResponse getErrorVCResponse();
}
