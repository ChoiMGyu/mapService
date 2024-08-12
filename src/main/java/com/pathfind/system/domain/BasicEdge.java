/*
 * 클래스 기능 : Edge 클래스에 필요한 함수들을 모아놓은 인터페이스
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.domain;

public interface BasicEdge {
    public Long getVertex1();
    public Long getVertex2();
    public double getLength();
}
