/*
 * 클래스 기능 : 커스텀 로그인 성공 핸들러
 * 최근 수정 일자 : 2024.08.08(목)
 */
package com.pathfind.system.handler;

import com.pathfind.system.authDto.PrincipalDetails;
import com.pathfind.system.domain.Member;
import com.pathfind.system.jwtDto.IssuedTokenCSResponse;
import com.pathfind.system.service.CookieServiceImpl;
import com.pathfind.system.service.JwtServiceImpl;
import com.pathfind.system.service.MemberService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final MemberService memberService;

    private final JwtServiceImpl jwtService;

    private final CookieServiceImpl cookieService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Login success");
        Member member = ((PrincipalDetails) authentication.getPrincipal()).getMember();
        logger.info("Login success userId: {}", member.getUserId());
        memberService.updateLastConnect(member.getUserId());
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
            for (Cookie cookie : request.getCookies()) {
                String name = cookie.getName();
                if (name.equals("JSESSIONID")) {
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                    break;
                }
            }
        }
        IssuedTokenCSResponse token = jwtService.createToken(member.getUserId());
        cookieService.addAccessTokenCookie(response, token.getAccessToken());
        cookieService.addRefreshTokenCookie(response, token.getRefreshToken());

        if (member.getUserId().contains("_")) response.sendRedirect("/");
        //현재는 쿠키를 사용하여 access, refresh token을 저장
        //웹을 설계할 때는 쿠키를 사용해도 되나, 모바일 앱인 경우는 쿠키를 사용하지 않으므로 refresh token 또한 헤더로 전달해야 함
        //보안 요구 사항에 따라 쿠키와 헤더를 결정
        //헤더를 사용할 경우 HTTPS를 위한 SSL 인증을 필수적으로 진행해야함
    }
}
