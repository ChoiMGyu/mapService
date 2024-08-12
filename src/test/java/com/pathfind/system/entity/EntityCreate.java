package com.pathfind.system.entity;

import com.pathfind.system.domain.Check;
import com.pathfind.system.domain.Member;
import com.pathfind.system.service.RedisUtil;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

@RunWith(SpringRunner.class)
@SpringBootTest
@Transactional
public class EntityCreate {

    @Autowired
    EntityManager em;

    @Test
    @DisplayName("회원엔티티생성")
    public void 회원엔티티생성() throws Exception
    {
        //given
        String userId = "Id";
        String password = "password";
        String nickname = "nickname";
        String email = "email";
        Check check = Check.createCheck();

        Member member = Member.createMember(userId, password, nickname, email, check);

        em.persist(member);

        //when
        Member findMember = em.find(Member.class, member.getId());

        //then
        Assertions.assertThat(member.getUserId()).isEqualTo(findMember.getUserId());
    }

}
