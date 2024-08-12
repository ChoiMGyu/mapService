/*
 * 클래스 기능 : objects 검색 목록을 사용자에게 보낼 때 사용하는 dto 이다.
 * 최근 수정 일자 : 2024.05.28(화)
 */
package com.pathfind.system.findPathDto;

import lombok.AllArgsConstructor;

import java.util.List;

@AllArgsConstructor
public class SearchObjectsNameVCResponse {
    public List<String> objectsNameList;
//    public int currentPage;
//    public int totalPages;
}
