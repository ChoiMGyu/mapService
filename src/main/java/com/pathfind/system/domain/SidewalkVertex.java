/*
 * 클래스 기능 : 도보 정점 정보 엔티티
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.domain;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
public class SidewalkVertex implements BasicVertex {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "sidewalk_vertex_id")
    private Long id; // SidewalkVertex 테이블 아이디

    @Column(nullable = false)
    private double latitude; // 정점의 위도

    @Column(nullable = false)
    private double longitude; // 정점의 경도

    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "is_destination")
    private Objects object; // 일대일 연관관계 매핑

    //==정적 팩토리 메서드==//
    public static SidewalkVertex createSidewalkVertex(Long id, double latitude, double longitude, Objects objects) {
        SidewalkVertex sidewalkVertex = new SidewalkVertex();
        sidewalkVertex.id = id;
        sidewalkVertex.latitude = latitude;
        sidewalkVertex.longitude = longitude;
        sidewalkVertex.object = objects;

        return sidewalkVertex;
    }

    //==연관관계 메소드==//
    public void changeObjects(Objects objects) {
        this.object = objects;
        objects.changeSidewalkVertex(this);
    }
    /*@OneToMany(mappedBy = "sidewalkVertex1", cascade = CascadeType.ALL)
    private List<SidewalkEdge> sidewalkEdges = new ArrayList<>();*/
}
