/*
 * 클래스 기능 : 건물, 랜드마크 등의 정보를 담는 오브젝트 엔티티
 * 최근 수정 일자 : 2024.02.13(화)
 */
package com.pathfind.system.domain;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
public class Objects {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "object_id")
    private Long id; // Object 테이블 아이디

    @Column(length = 45, nullable = false)
    private String name; // 이름

    @Column(length = 1000)
    private String description; //  대상의 설명

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ObjType objectType; // 대상의 종류(건물, 랜드마크, 벤치 등등)

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "address_id")
    private ObjectAddress objectAddress;

    @OneToOne(mappedBy = "object", fetch = FetchType.LAZY)
    private RoadVertex roadVertex; //RoadVertex와 Objects 양방향 연관관계

    @OneToOne(mappedBy = "object", fetch = FetchType.LAZY)
    private SidewalkVertex sidewalkVertex; //SidewalkVertex와 Objects 양방향 연관관계

    //==연관관계 메소드를 위한 setter==//
    public void changeRoadVertex(RoadVertex roadVertex) { this.roadVertex = roadVertex; }

    public void changeSidewalkVertex(SidewalkVertex sidewalkVertex) { this.sidewalkVertex = sidewalkVertex; }

}
