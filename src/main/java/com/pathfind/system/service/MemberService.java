/*
 * 클래스 기능 : 회원 서비스 인터페이스
 * 최근 수정 일자 : 2024.05.17(금)
 */
package com.pathfind.system.service;

import com.pathfind.system.domain.Member;

import java.util.List;
import java.util.Optional;

public interface MemberService {
    public List<Member> findByUserId(Member member);

    public List<Member> findByNickname(Member member);

    public List<Member> findByEmail(Member member);

    public Long register(Member member);

    public Member updatePassword(Long id, String oldPassword, String newPassword1, String newPassword2);

    public Member login(String userId, String password);

    public void updateLastConnect(String userId);

    public List<String> findUserIdByEmail(String email);

    public boolean idEmailChk(String userId, String email);

    public void findPassword(String userId, String email);

    public void recoverMember(Long id);

    public Optional<Member> updateNickname(Long id, String nickname);

    public Member updateEmail(Long id, String email);

    public void deleteMember(Long id);

    public List<String> findNicknameListBySearchWord(String searchWord);
}
