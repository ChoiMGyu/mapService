/*
 * 클래스 기능 : 동의 여부 체크 엔티티
 * 최근 수정 일자 : 2024.01.05(금)
 */
package com.pathfind.system.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@EqualsAndHashCode
@Table(name = "checks")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Check {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "check_id")
    private Long id; //Check 테이블 PK

    @Column(nullable = false, columnDefinition = "TINYINT(1)")
    private boolean emailAuth; //이메일 인증

    @Column(nullable = false, columnDefinition = "TINYINT(1)")
    private boolean informationAgree; //개인정보 수집동의

    @Column(nullable = false, columnDefinition = "TINYINT(1)")
    private boolean dormant; //휴먼계정 여부확인

    //==정적 팩토리 메서드==//
    public static Check createCheck() {
        Check check = new Check();
        check.changeEmailAuth(false);
        check.changeInformationAgree(false);
        check.changeDormant(false);

        return check;
    }

    //==비지니스 로직==//
    public void changeEmailAuth(boolean emailAuth) {
        this.emailAuth = emailAuth;
    }

    public void changeInformationAgree(boolean informationAgree) {
        this.informationAgree = informationAgree;
    }

    public void changeDormant(boolean dormant) {
        this.dormant = dormant;
    }
}
