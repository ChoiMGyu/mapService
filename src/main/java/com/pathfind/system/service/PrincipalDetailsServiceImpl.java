/*
 * 클래스 기능 : 일반 로그인 시 PrincipalDetails(UserDetails 구현체)를 만들기 위해 사용되는 클래스
 * 최근 수정 일자 : 2024.05.19(일)
 */
package com.pathfind.system.service;

import com.pathfind.system.authDto.PrincipalDetails;
import com.pathfind.system.domain.Member;
import com.pathfind.system.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/*
 * SecurityConfig에서 loginProcessingUrl("/login")으로 설정해 놓았기 때문에
 * login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수가 실행된다.
 * */
@Service
@RequiredArgsConstructor
public class PrincipalDetailsServiceImpl implements UserDetailsService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final MemberRepository memberRepository;

    public UserDetails loadUserByUsername(String userId) {
        //logger.info("userId: {}", userId);
        List<Member> memberList = memberRepository.findByUserID(userId);
        if (!memberList.isEmpty()) {
            return new PrincipalDetails(memberList.get(0));
        }
        throw new UsernameNotFoundException(userId);
    }
}
