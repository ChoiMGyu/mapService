package com.pathfind.system.findPathService2Domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode
@AllArgsConstructor
@NoArgsConstructor
public class MemberLatLng {
    private double latitude; // 위도
    private double longitude; // 경도
}
