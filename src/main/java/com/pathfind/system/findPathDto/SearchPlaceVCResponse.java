/*
 * 클래스 기능 : 검색 로직 반환 Response
 * 최근 수정 일자 : 2024.02.16(금)
 */
package com.pathfind.system.findPathDto;

import com.pathfind.system.domain.ObjType;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SearchPlaceVCResponse {

    @NotEmpty
    private String name; // 이름

    @NotEmpty
    private String description; //  대상의 설명

    @NotEmpty
    private String address; // 주소

    @NotEmpty
    private ObjType objectType; // 대상의 종류(건물, 랜드마크, 벤치 등등)

    @NotEmpty
    private double Latitude;

    @NotEmpty
    private double Longitude;

    private Long roadVertexId;

    private Long sidewalkVertexId;
}
