/*
 * 클래스 기능 : 이동 수단 속도 정보 엔티티
 * 최근 수정 일자 : 2024.01.05(금)
 */
package com.pathfind.system.domain;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
public class TransportationSpeedInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "transportation_speed_info_id")
    private Long id; // TransportationSpeedInfo 테이블 아이디

    @Column(nullable = false)
    private String name; // 이동 수단 이름

    @Column(nullable = false)
    private int speed; // 이동 수단 평균 속도(km/h)
}
