/*
 * 클래스 기능 : 장소 검색을 위해 만든 Request
 * 최근 수정 일자 : 2024.02.15(목)
 */
package com.pathfind.system.findPathDto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SearchPlaceVCRequest {

    @NotBlank(message = "검색 내용을 입력해주세요")
    private String searchContent;
}
