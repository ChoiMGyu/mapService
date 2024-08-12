/*
 * 클래스 기능 : 회원 리포지토리 구현 클래스
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.repository;

import com.pathfind.system.domain.Member;
import io.lettuce.core.dynamic.annotation.Param;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class MemberRepositoryImpl implements MemberRepository {

    private final EntityManager em;

    @Override
    public List<Member> findByUserID(String userId) {
        return em.createQuery("select m from Member m" +
                        " join fetch" +
                        " m.check where m.userId = :userId", Member.class)
                .setParameter("userId", userId)
                .getResultList();
    }

    @Override
    public List<Member> findByNickname(String nickname) {
        return em.createQuery("select m from Member m" +
                        " join fetch m.check" +
                        " where m.nickname = :nickname", Member.class)
                .setParameter("nickname", nickname)
                .getResultList();
    }

    @Override
    public List<Member> findByEmail(String email) {
        return em.createQuery("select m from Member m" +
                        " join fetch m.check" +
                        " where m.email = :email", Member.class)
                .setParameter("email", email)
                .getResultList();
    }

    @Override
    public void register(Member member) {
        em.persist(member.getCheck());
        em.persist(member);
    }

    @Override
    public Member findByID(Long id) {
        return em.createQuery("select m from Member m" +
                        " join fetch m.check" +
                        " where m.id = :id" , Member.class)
                .setParameter("id", id)
                .getSingleResult();
        //return em.find(Member.class, id);
    }

    @Override
    public List<Member> login(String userId, String password) {
        return em.createQuery("select m from Member m" +
                        " join fetch m.check" +
                        " where m.userId = :userId and m.password = :password", Member.class)
                .setParameter("userId", userId)
                .setParameter("password", password)
                .getResultList();
    }

    @Override
    public List<String> findUserIdByEmail(String email) {
        return em.createQuery("select m.userId from Member m" +
                        " where m.email = :email", String.class)
                .setParameter("email", email)
                .getResultList();
    }

    @Override
    public void deleteMember(Member member) {
        em.remove(member);
        em.remove(member.getCheck());
    }

    @Override
    public List<String> findAllNickname() {
        return em.createQuery("select m.nickname from Member m", String.class)
                .getResultList();
    }

    @Override
    public List<Member> findAllDormant(@Param("inActive")LocalDateTime inActive) {
        return em.createQuery("select m from Member m where m.lastConnect < :inActive", Member.class)
                .getResultList();
    }
}
