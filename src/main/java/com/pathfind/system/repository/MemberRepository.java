/*
 * 클래스 기능 : 회원 리포지토리 인터페이스
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.repository;

import com.pathfind.system.domain.Member;
import io.lettuce.core.dynamic.annotation.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface MemberRepository {
    public List<Member> findByUserID(String userId);

    public List<Member> findByNickname(String nickname);

    public List<Member> findByEmail(String email);

    public void register(Member member);

    public Member findByID(Long id);

    public List<Member> login(String userId, String password);

    public List<String> findUserIdByEmail(String email);

    void deleteMember(Member member);

    public List<String> findAllNickname();

    public List<Member> findAllDormant(@Param("inActive") LocalDateTime inActive);
}
