/*
 * 클래스 기능 : 휴먼계정정보 엔티티
 * 최근 수정 일자 : 2024.01.05(금)
 */
package com.pathfind.system.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

/*@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Dormant {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "dormant_id")
    private Long id; //휴먼계정테이블 PK

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;

    private LocalDate dormantStartDate; //휴먼계정 시작일 -> member.lastConnect와 연관

    //==정적 팩토리 메서드==//
    public static Dormant createDormant(Member member) {
        Dormant dormant = new Dormant();
        dormant.initialMember(member);
        dormant.changeDormantStartDate(LocalDate.now());

        return dormant;
    }

    private void initialMember(Member member) {
        this.member = member;
    }

    public void changeDormantStartDate(LocalDate date) {
        this.dormantStartDate = date;
    }

}*/
