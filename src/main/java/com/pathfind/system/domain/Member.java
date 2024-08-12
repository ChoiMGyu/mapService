/*
 * 클래스 기능 : 회원정보 엔티티
 * 최근 수정 일자 : 2024.08.02(금)
 */
package com.pathfind.system.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.Objects;
import java.util.regex.Pattern;

@Entity
//@Table(
//        name = "MemberUniqueConstraint",
//        uniqueConstraints = {
//                @UniqueConstraint(columnNames = {"userId", "nickname", "email"})
//        }
//)
@Getter
@EqualsAndHashCode
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id; //Member 테이블 PK

    @Column(length = 12, nullable = false)
    private String userId; //아이디

    @Column(nullable = false)
    private String password; //비밀번호 // 변경 가능

    @Column(length = 12, nullable = false)
    private String nickname; //닉네임 // 변경 가능

    @Column(length = 45, nullable = false)
    private String email; //이메일

    @Column(nullable = false)
    private LocalDate joinDate; //가입일자 // 변경 가능

    @Column(nullable = false)
    private LocalDate lastConnect; //최근접속일 // 변경 가능

    @OneToOne(fetch = FetchType.LAZY) //OneToOne은 기본 Eager
    @JoinColumn(name = "check_id")
    private Check check; //일대일 연관관계 매핑

    //==정적 팩토리 메서드==//
    public static Member createMember(String userId, String password, String nickname, String email, Check check) {
        Member member = new Member();
        member.initialUserId(userId);
        member.changePassword(password);
        member.changeNickname(nickname);
        member.initialEmail(email);
        member.changeJoinDate(LocalDate.now());
        member.changeLastConnect(LocalDate.now());
        member.initialCheck(check);

        return member;
    }

    //==setter 방지 메서드==//
    private void initialUserId(String userId) {
        this.userId = userId;
    }

    public void initialEmail(String email) {
        this.email = email;
    }

    private void initialCheck(Check check) {
        this.check = check;
    }

    //==비지니스 로직==//
    public void changeId(Long id) {
        this.id = id;
    }

    public void changeUserId(String userId) {
        this.userId = userId;
    }

    public void changePassword(String password) {
        this.password = password;
    }

    public void changeNickname(String nickname) {
        this.nickname = nickname;
    }

    public void changeEmail(String email) {
        this.email = email;
    }

    public void changeJoinDate(LocalDate date) {
        this.joinDate = date;
    }

    public void changeLastConnect(LocalDate date) {
        this.lastConnect = date;
    }

    public void changeCheck(Check check) {this.check = check;}

    public String updateToTemporaryPassword() {
        String temporaryPassword = getRandomPassword();
        this.changePassword(temporaryPassword);
        return temporaryPassword;
    }

    private String getRandomPassword() {
        SecureRandom random = new SecureRandom();
        String patternPassword = "(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,20}";
        StringBuilder randomPassword;
        boolean regexPassword;
        do {
            randomPassword = new StringBuilder();
            for (int i = 0; i < 14; i++) {
                int nextType = (int) (random.nextFloat() * 4);
                if (nextType == 0) randomPassword.append((char) (48 + random.nextInt(10)));
                else if (nextType == 1) randomPassword.append((char) (65 + random.nextInt(26)));
                else if (nextType == 2) randomPassword.append((char) (97 + random.nextInt(26)));
                else {
                    while (true) {
                        int c = 33 + random.nextInt(94);
                        if (c != 34 && c != 39 && c != 92) {
                            randomPassword.append((char) c);
                            break;
                        }
                    }
                }
            }
            regexPassword = Pattern.matches(patternPassword, randomPassword.toString());
        } while (!regexPassword);
        return randomPassword.toString();
    }

    public boolean checkPassword(String password) {
        return this.password.equals(password);
    }

    public static String createRandomUserId(int size) {
        SecureRandom random = new SecureRandom();
        String patternUserId = "(?=.*[0-9])(?=.*[a-zA-Z]).{0,12}";
        StringBuilder randomUserId;
        boolean regexUserId;
        do {
            randomUserId = new StringBuilder();
            for (int i = 0; i < size; i++) {
                int nextType = random.nextInt(3);
                if (nextType == 0) randomUserId.append((char) (48 + random.nextInt(10)));
                else if (nextType == 1) randomUserId.append((char) (65 + random.nextInt(26)));
                else randomUserId.append((char) (97 + random.nextInt(26)));
            }
            regexUserId = Pattern.matches(patternUserId, randomUserId.toString());
        } while (!regexUserId);
        return randomUserId.toString();
    }
}
