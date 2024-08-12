/*
 * 클래스 기능 : 회원 리포지토리 테스트
 * 최근 수정 일자 : 2024.01.09(화)
 */
package com.pathfind.system.repository;

import com.pathfind.system.domain.Check;
import com.pathfind.system.domain.Member;
import jakarta.persistence.EntityManager;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@RunWith(SpringRunner.class)
@SpringBootTest
@Transactional
//@DataJpaTest
//@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class MemberRepositoryTest {
    @Autowired
    MemberRepository memberRepository;

    @Autowired
    EntityManager em;

    @Test
    public void 등록_확인() throws Exception {
        //given
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", Check.createCheck());

        //when
        memberRepository.register(member);
        Long id = member.getId();
        Member result = em.createQuery("select m from Member m where id = :id", Member.class)
                .setParameter("id", id)
                .getSingleResult();

        //then
        Assert.assertEquals(member, result);
    }

    @Test
    public void 아이디로_찾기() throws Exception {
        //given
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", null);
        em.persist(member);

        //when
        List<Member> result = memberRepository.findByUserID(member.getUserId());

        //then
        Assert.assertEquals(member, result.get(0));
    }

    @Test
    public void 닉네임으로_찾기() throws Exception {
        //given
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", null);
        em.persist(member);

        //when
        List<Member> result = memberRepository.findByNickname(member.getNickname());


        //then
        Assert.assertEquals(member, result.get(0));
    }

    @Test
    public void 이메일로_찾기() throws Exception {
        //given
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", null);
        em.persist(member);

        //when
        List<Member> result = memberRepository.findByEmail(member.getEmail());

        //then
        Assert.assertEquals(member, result.get(0));
    }

    @Test
    public void 아이디_회원찾기() throws Exception
    {
        //given
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", Check.createCheck());

        //when
        memberRepository.register(member);
        Member findMember = memberRepository.findByID(member.getId());

        //then
        Assert.assertEquals(findMember, member);
    }

    @Test
    public void 로그인_성공() throws Exception {
        //given
        Check check = Check.createCheck();
        em.persist(check);
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", check);
        String id = member.getUserId(), password = member.getPassword();
        em.persist(member);
        em.flush();
        em.clear();

        //when
        List<Member> result = memberRepository.login(id, password);

        //then
        Assert.assertTrue(member.equals(result.get(0)));
    }

    @Test
    public void 로그인_실패() throws Exception {
        //given
        Check check = Check.createCheck();
        em.persist(check);
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", check);
        String id = "fakeUser", password = "fakePassword";
        em.persist(member);
        em.flush();
        em.clear();

        //when
        List<Member> result = memberRepository.login(id, password);

        //then
        Assert.assertTrue(result.isEmpty());
    }

    @Test
    public void 이메일로_아이디_찾기_성공() throws Exception {
        //given
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", null);
        String id = member.getUserId(), email = member.getEmail();
        em.persist(member);
        em.flush();
        em.clear();

        //when
        List<String> result = memberRepository.findUserIdByEmail(email);

        //then
        Assert.assertEquals(id, result.get(0));
    }

    @Test
    public void 이메일로_아이디_찾기_실패() throws Exception {
        //given
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", null);
        String email = "fakeEmail@hello.net";
        em.persist(member);
        em.flush();
        em.clear();

        //when
        List<String> result = memberRepository.findUserIdByEmail(email);

        //then
        Assert.assertTrue(result.isEmpty());
    }

    @Test
    public void 회원_삭제() throws Exception {
        //given
        Check check = Check.createCheck();
        em.persist(check);
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", check);
        em.persist(member);
        Long id = member.getId();

        //when
        memberRepository.deleteMember(member);
        em.flush();
        em.clear();

        //then
        Assert.assertNull(em.find(Member.class, id));
    }

}