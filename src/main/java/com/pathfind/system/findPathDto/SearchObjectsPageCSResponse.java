/*
 * 클래스 기능 : 페이지의 구성 정보를 설정하는 클래스이다.
 * 최근 수정 일자 : 2024.06.01(토)
 */
package com.pathfind.system.findPathDto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SearchObjectsPageCSResponse {
    public int page;
    public int size;
}
