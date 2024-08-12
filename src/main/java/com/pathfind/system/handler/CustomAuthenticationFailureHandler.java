/*
 * 클래스 기능 : 커스텀 로그인 실패 핸들러
 * 최근 수정 일자 : 2024.08.08(목)
 */
package com.pathfind.system.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pathfind.system.memberDto.LoginFailureVCResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        logger.info("Login failed");
        String message = "";
        if (exception instanceof BadCredentialsException || exception instanceof InternalAuthenticationServiceException) {
            message = "아이디 또는 비밀번호가 맞지 않습니다.";
        }
        else if (exception instanceof OAuth2AuthenticationException) {
            message = ((OAuth2AuthenticationException) exception).getError().getErrorCode();
        }

        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());

        LoginFailureVCResponse loginFailureVCResponse = new LoginFailureVCResponse(message);
        String result = objectMapper.writeValueAsString(loginFailureVCResponse);
        response.getWriter().print(result);
    }
}
