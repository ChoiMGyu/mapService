/*
 * 클래스 기능 : 도보 간선 정보 엔티티
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.domain;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
public class SidewalkEdge implements BasicEdge  {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "sidewalk_edge_id")
    private Long id; // SidewalkEdge 테이블 아이디

    //@ManyToOne(fetch = FetchType.LAZY)
    @Column(name = "sidewalk_vertex_id1", nullable = false)
    private Long sidewalkVertex1; // 보도 정점1(시작)

    //@ManyToOne(fetch = FetchType.LAZY)
    @Column(name = "sidewalk_vertex_id2", nullable = false)
    private Long sidewalkVertex2; // 도보 정점2(끝)

    @Column(nullable = false)
    private double length; // 간선 길이

    //==정적 팩토리 메서드==//
    public static SidewalkEdge createSidewalkEdge(Long id, Long sidewalkVertex1, Long sidewalkVertex2, double length) {
        SidewalkEdge sidewalkEdge = new SidewalkEdge();
        sidewalkEdge.id = id;
        sidewalkEdge.sidewalkVertex1 = sidewalkVertex1;
        sidewalkEdge.sidewalkVertex2 = sidewalkVertex2;
        sidewalkEdge.length = length;

        return sidewalkEdge;
    }

    public Long getVertex1() {
        return sidewalkVertex1;
    }

    public Long getVertex2() {
        return sidewalkVertex2;
    }
}
