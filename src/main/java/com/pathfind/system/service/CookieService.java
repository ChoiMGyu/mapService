package com.pathfind.system.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface CookieService {

    public void addAccessTokenCookie(HttpServletResponse response, String accessToken);

    public void deleteAccessTokenCookie(HttpServletResponse response, String accessToken);

    public void addRefreshTokenCookie(HttpServletResponse response, String refreshToken);

    public void deleteRefreshTokenCookie(HttpServletResponse response, String refreshToken);

    public String findAccessToken(HttpServletRequest request);

    public String findRefreshToken(HttpServletRequest request);
}
