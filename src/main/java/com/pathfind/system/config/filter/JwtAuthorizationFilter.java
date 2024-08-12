/*
 * 클래스 기능 : 인가(Authorization)를 하는 필터 클래스이다.
 * 최근 수정 일자 : 2024.08.08(목)
 */
package com.pathfind.system.config.filter;

import com.pathfind.system.authDto.PrincipalDetails;
import com.pathfind.system.domain.Member;
import com.pathfind.system.repository.MemberRepository;
import com.pathfind.system.service.CookieServiceImpl;
import com.pathfind.system.service.JwtServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final JwtServiceImpl jwtService;

    private final MemberRepository memberRepository;

    private final CookieServiceImpl cookieService;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository, JwtServiceImpl jwtService, CookieServiceImpl cookieService) {
        super(authenticationManager);
        this.memberRepository = memberRepository;
        this.jwtService = jwtService;
        this.cookieService = cookieService;
    }

    // 모든 주소 요청이 있을 때 해당 필터를 타게 된다. if문을 통해 authorization이 필요없는 주소는 다음 필터로 넘어가게 한다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // request에서 token 추출
        String accessToken = cookieService.findAccessToken(request);
        String refreshToken = cookieService.findRefreshToken(request);

        if (request.getRequestURL().toString().contains("message")) { // || !authorization.startsWith(JwtProperties.TOKEN_PREFIX)
            chain.doFilter(request, response);
            return;
        }
        if (accessToken != null && refreshToken==null) {
            throw new JwtException("Refresh Token is not valid!!!");
        }

        // header가 있는지 확인
        if (request.getRequestURL().toString().contains("/img") || request.getRequestURL().toString().contains("/css") || request.getRequestURL().toString().contains("/js") || refreshToken == null) { // || !authorization.startsWith(JwtProperties.TOKEN_PREFIX)
            chain.doFilter(request, response);
            return;
        }

        logger.info("인증이나 권한이 필요한 주소 요청이 있음");
        logger.info(request.getRequestURL().toString());
        logger.info("JwtHeader Authorization: " + accessToken + ", Authorization refresh: " + refreshToken);

        // 서명 유효성 확인
        if (accessToken == null) {
            accessToken = jwtService.reIssueAccessToken(refreshToken);
//            if(accessToken == null) {
//                throw new JwtException("Refresh token is not valid");
//            }
            cookieService.addAccessTokenCookie(response, accessToken);
        }

        String userId = jwtService.getUserId(accessToken);

        Member member = memberRepository.findByUserID(userId).get(0);

        PrincipalDetails principalDetails = new PrincipalDetails(member);

        // JWT 토큰 서명을 통해 서명이 정상이면 Authentication 객체를 만들어준다.
        Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

        // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        chain.doFilter(request, response);
    }
}
