/*
 * 클래스 기능 : 로그인 시 사용되는 필터이다. 인증(Authentication)을 하는 필터 클래스이다.
 * 최근 수정 일자 : 2024.08.08(목)
 */
package com.pathfind.system.config.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pathfind.system.authDto.PrincipalDetails;
import com.pathfind.system.domain.Member;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음.
// /login 요청해서 username, password 전송하면(post) 동작함.
// 그러나 security config에서 formlogin disable을 했기 때문에 UsernamePasswordAuthenticationFilter가 동작하지 않음.
// 따라서 UsernamePasswordAuthenticationFilter를 다시 security config에 등록해주어야 한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수이다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        logger.info("JwtAuthenticationFilter: 로그인 시도중");

        try {
            ObjectMapper om = new ObjectMapper();
            Member member = om.readValue(request.getInputStream(), Member.class);
            logger.info("로그인을 시도한 유저의 userId: {}", member.getUserId());

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(member.getUserId(), member.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴된다.
            // DB에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // => 로그인이 되었다는 뜻. (아래는 확인 차원)
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            logger.info("Authentication을 모두 마친 유저: " + principalDetails.getMember().getUserId()); // 로그인이 정상적으로 되었다는 뜻.
            // authentication 객체가 session 영역에 저장된다. => 출력이 된다면 로그인이 되었다는 것이다.
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것이다.
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 단지 권한 처리 때문에 session을 넣어준다.

            return authentication;
        } catch (IOException e) {
            logger.info("로그인을 시도하는 과정에서 오류가 발생하였음!");
            throw new RuntimeException(e);
        }
    }
}
