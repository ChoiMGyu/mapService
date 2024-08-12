/*
 * 클래스 기능 : 페이지를 구성하는 object 객체이다.
 * 최근 수정 일자 : 2024.05.31(금)
 */
package com.pathfind.system.findPathDto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
public class PageObject {
    private String name;
    private double longitude;
    private double latitude;
}
