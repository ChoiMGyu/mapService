/*
 * 클래스 기능 : 회원 서비스 클래스
 * 최근 수정 일자 : 2024.05.30(목)
 */
package com.pathfind.system.service;

import com.pathfind.system.controller.MemberController;
import com.pathfind.system.domain.Member;
import com.pathfind.system.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cglib.core.Local;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.*;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberServiceImpl implements MemberService {

    private static final Logger logger = LoggerFactory.getLogger(MemberServiceImpl.class);

    private final MemberRepository memberRepository;
    private final MailSendService mailSendService;
    private final RedisUtil redisUtil;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public List<Member> findByUserId(Member member) {
        return memberRepository.findByUserID(member.getUserId());
    }

    @Override
    public List<Member> findByNickname(Member member) {
        return memberRepository.findByNickname(member.getNickname());
    }

    @Override
    public List<Member> findByEmail(Member member) {
        return memberRepository.findByEmail(member.getEmail());
    }

    @Override
    @Transactional
    public Long register(Member member) {
        memberRepository.register(member);
        List<String> data = new ArrayList<>();
        data.add(member.getNickname());
        redisUtil.setDataSortedSet(RedisValue.NICKNAME_SET, data);
        return member.getId();
    }

    @Override
    @Transactional
    public Member updatePassword(Long id, String oldPassword, String newPassword1, String newPassword2) {
        Member findMember = memberRepository.findByID(id);
        logger.info("service에서 호출한 findMember 객체 : " + findMember);

        if (bCryptPasswordEncoder.matches(oldPassword, findMember.getPassword())) {
            if (newPassword1.equals(newPassword2)) {
                findMember.changePassword(bCryptPasswordEncoder.encode(newPassword1));
                return findMember;
            } else {
                return findMember;
            }
        } else {
            return findMember;
        }
    }

    @Override
    @Transactional
    public void recoverMember(Long id) {
        Member findMember = memberRepository.findByID(id);
        findMember.getCheck().changeDormant(false);
    }

    @Override
    public Member login(String userId, String password) {
        List<Member> result = memberRepository.login(userId, password);

        if (result.isEmpty()) {
            //throw new IllegalStateException("아이디 혹은 비밀번호가 틀렸습니다.");
            return null;
        }

        return result.get(0);
    }

    @Override
    @Transactional
    public void updateLastConnect(String userId) {
        List<Member> findMember = memberRepository.findByUserID(userId);
        findMember.get(0).changeLastConnect(LocalDate.now());
    }

    @Override
    public List<String> findUserIdByEmail(String email) {
        return memberRepository.findUserIdByEmail(email);
    }

    @Override
    public boolean idEmailChk(String userId, String email) {
        List<Member> findByUserID = memberRepository.findByUserID(userId);
        List<Member> findByEmail = memberRepository.findByEmail(email);

        return !findByUserID.isEmpty() && !findByEmail.isEmpty() && findByUserID.get(0).equals(findByEmail.get(0));
        //throw new IllegalStateException("회원 정보가 일치하지 않습니다.");
    }

    @Override
    @Transactional
    public void findPassword(String userId, String email) {
        String temporaryPassword = updateToTemporaryPassword(userId);
        mailSendService.findPasswordEmail(email, temporaryPassword);
    }

    private String updateToTemporaryPassword(String userId) {
        Member result = memberRepository.findByUserID(userId).get(0);
        String temporaryPassword = result.updateToTemporaryPassword();
        result.changePassword(bCryptPasswordEncoder.encode(temporaryPassword));
        return temporaryPassword;
    }

    @Override
    @Transactional
    public Optional<Member> updateNickname(Long id, String nickname) {
        Member result = memberRepository.findByID(id);
        List<Member> isDuplicated = memberRepository.findByNickname(nickname);
        if (!isDuplicated.isEmpty()) return Optional.empty();
        redisUtil.deleteDataFromSortedSet(RedisValue.NICKNAME_SET, result.getNickname());
        result.changeNickname(nickname);
        List<String> data = new ArrayList<>();
        data.add(nickname);
        redisUtil.setDataSortedSet(RedisValue.NICKNAME_SET, data);
        return Optional.ofNullable(result);
    }

    @Override
    @Transactional
    public Member updateEmail(Long id, String email) {
        Member result = memberRepository.findByID(id);
        result.changeEmail(email);
        return result;
    }

    @Override
    @Transactional
    public void deleteMember(Long id) {
        Member result = memberRepository.findByID(id);
        redisUtil.deleteDataFromSortedSet(RedisValue.NICKNAME_SET, result.getNickname());
        memberRepository.deleteMember(result);
    }

    @Override
    public List<String> findNicknameListBySearchWord(String searchWord) {
        logger.info("Find nickname list by search word. search word: {}", searchWord);
        if (redisUtil.getDataSortedSet(RedisValue.NICKNAME_SET, RedisValue.GET_ALL_DATA).isEmpty()) {
            redisUtil.setDataSortedSet(RedisValue.NICKNAME_SET, memberRepository.findAllNickname());
        }
        List<String> result = redisUtil.getDataSortedSet(RedisValue.NICKNAME_SET, searchWord);
        //logger.info("result: {}", result);
        Comparator<String> comparingIndexOf = Comparator.comparingInt(a -> a.indexOf(searchWord));
        result.sort(comparingIndexOf.thenComparing(Comparator.naturalOrder()));

        List<String> response = new ArrayList<>();
        for(int i = 0; i < Math.min(5,result.size()); i++) {
            response.add(result.get(i));
        }
        return response;
    }
}
