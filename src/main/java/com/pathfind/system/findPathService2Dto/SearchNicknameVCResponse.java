/*
 * 클래스 기능 : 닉네임 검색 목록을 사용자에게 보낼 때 사용하는 dto 이다.
 * 최근 수정 일자 : 2024.04.10(화)
 */
package com.pathfind.system.findPathService2Dto;

import lombok.AllArgsConstructor;

import java.util.List;

@AllArgsConstructor
public class SearchNicknameVCResponse {
    public List<String> nicknameList;
}
