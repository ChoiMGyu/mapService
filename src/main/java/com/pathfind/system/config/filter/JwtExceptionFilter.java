/*
 * 클래스 기능 : JWT authorizationFilter에서 예외 발생 시 메인 페이지로 이동시키는 역할을 하는 필터 클래스이다.
 * 최근 수정 일자 : 2024.08.08(목)
 */
package com.pathfind.system.config.filter;

import com.pathfind.system.service.CookieServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtExceptionFilter extends OncePerRequestFilter {

    //private final ObjectMapper objectMapper;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final CookieServiceImpl cookieService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (JwtException e) {
            logger.info("fail to authorization");
            /*response.setContentType("application/json");
            response.setCharacterEncoding("utf-8");
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            AuthorizationFailureVCResponse authorizationFailureVCResponse = new AuthorizationFailureVCResponse("Authorization failed!!!");
            String result = objectMapper.writeValueAsString(authorizationFailureVCResponse);
            response.getWriter().print(result);*/
            logger.info("Jwt Exception: {}", e.getMessage());
            String accessToken = cookieService.findAccessToken(request);
            String refreshToken = cookieService.findRefreshToken(request);
            if (accessToken != null) cookieService.deleteAccessTokenCookie(response, accessToken);
            if (refreshToken != null) cookieService.deleteRefreshTokenCookie(response, refreshToken);
            /*logger.info("request url: " + request.getRequestURL());
            logger.info("request uri: " + request.getRequestURI());*/
            String redirectUrl = UriComponentsBuilder.fromHttpUrl(request.getRequestURL().replace(request.getRequestURL().length() - request.getRequestURI().length(), request.getRequestURL().length(), "").toString())
                    //.queryParam("message", e.getMessage())
                    .toUriString();

            // 302 Redirect 응답을 설정
            response.setStatus(HttpServletResponse.SC_FOUND);
            response.setHeader("Location", redirectUrl);
        }
    }
}
