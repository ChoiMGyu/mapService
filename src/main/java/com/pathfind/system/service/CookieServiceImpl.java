/*
 * 클래스 기능 : Cookie 관련 서비스를 제공하는 클래스
 * 최근 수정 일자 : 2024.08.08(목)
 */
package com.pathfind.system.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CookieServiceImpl implements CookieService {

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.prefix}")
    private String BEARER_;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationPeriod;

    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationPeriod;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public void addAccessTokenCookie(HttpServletResponse response, String accessToken) {
        Cookie accessCookie = new Cookie(accessHeader, BEARER_ + accessToken);
        accessCookie.setSecure(true);
        accessCookie.setHttpOnly(true);
        accessCookie.setMaxAge((int) (accessTokenExpirationPeriod / 1000));
        accessCookie.setPath("/");
        response.addCookie(accessCookie);
    }

    public void deleteAccessTokenCookie(HttpServletResponse response, String accessToken) {
        Cookie accessCookie = new Cookie(accessHeader, BEARER_ + accessToken);
        accessCookie.setMaxAge(0);
        accessCookie.setPath("/");
        response.addCookie(accessCookie);
    }

    public void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshCookie = new Cookie(refreshHeader, BEARER_ + refreshToken);
        refreshCookie.setSecure(true);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setMaxAge((int) (refreshTokenExpirationPeriod / 1000));
        refreshCookie.setPath("/");
        response.addCookie(refreshCookie);
    }

    public void deleteRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshCookie = new Cookie(accessHeader, BEARER_ + refreshToken);
        refreshCookie.setMaxAge(0);
        refreshCookie.setPath("/");
        response.addCookie(refreshCookie);
    }

    public String findAccessToken(HttpServletRequest request) {
        String res = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                String name = cookie.getName();
                String token = cookie.getValue();
                //logger.info("cookie name: " + name + ", value: " + token);
                if (name.equals(accessHeader)) {
                    if (token.startsWith(BEARER_)) res = token.replace(BEARER_, "");
                    break;
                }
            }
        }
        return res;
    }

    public String findRefreshToken(HttpServletRequest request) {
        String res = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                String name = cookie.getName();
                String token = cookie.getValue();
                //logger.info("cookie name: " + name + ", value: " + token);
                if (name.equals(refreshHeader)) {
                    if (token.startsWith(BEARER_)) res = token.replace(BEARER_, "");
                    break;
                }
            }
        }
        return res;
    }
}
