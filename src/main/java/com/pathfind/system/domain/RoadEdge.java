/*
 * 클래스 기능 : 도로 간선 정보 엔티티
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.domain;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
public class RoadEdge implements BasicEdge {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "road_edge_id")
    private Long id; // RoadEdge 테이블 아이디

    //@ManyToOne(fetch = FetchType.LAZY)
    @Column(name = "road_vertex_id1", nullable = false)
    private Long roadVertex1; // 도로 정점1(시작)

    //@ManyToOne(fetch = FetchType.LAZY)
    @Column(name = "road_vertex_id2", nullable = false)
    private Long roadVertex2; // 도로 정점2(끝)

    @Column(nullable = false)
    private double length; // 간선 길이

    //==정적 팩토리 메서드==//
    public static RoadEdge createRoadEdge(Long id, Long roadVertex1, Long roadVertex2, double length) {
        RoadEdge roadEdge = new RoadEdge();
        roadEdge.id = id;
        roadEdge.roadVertex1 = roadVertex1;
        roadEdge.roadVertex2 = roadVertex2;
        roadEdge.length = length;

        return roadEdge;
    }

    public Long getVertex1() {
        return roadVertex1;
    }

    public Long getVertex2() {
        return roadVertex2;
    }

    /*@Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OneWayType oneWayType; // 일방통행 여부(YES, NO)*/
}
