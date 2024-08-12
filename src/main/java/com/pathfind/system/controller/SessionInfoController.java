/*
 * 클래스 기능 : 세션의 정보를 출력할 때 사용하는 controller
 * 최근 수정 일자 : 2024.01.16(화)
 */
package com.pathfind.system.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@Slf4j
@RestController
public class SessionInfoController {

    @GetMapping("/session-info")
    public String sessionInfo(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "세션이 없습니다.";
        }
        // 세션 id와 저장된 객체 정보 출력
        System.out.println(session.getId() + ", " + session.getAttribute("loginMember"));

        //세션 데이터 출력
        session.getAttributeNames().asIterator()
                .forEachRemaining(name -> log.info("session name={}, value={}", name, session.getAttribute(name)));

        log.info("sessionId={}", session.getId()); //JSESSIONID 값
        log.info("getMaxInactiveInterval={}", session.getMaxInactiveInterval()); //세션의 유효기간
        log.info("creationTime={}", new Date(session.getCreationTime())); //세션 생성일시
        log.info("lastAccessedTime={}", new Date(session.getLastAccessedTime())); //세션과 연결된 사용자가 최근에 서버에 접근한 시간
        log.info("isNew={}", session.isNew()); //새로 생성된 세션인지, 이전에 만들어졌는지 판별

        return "세션 출력";

    }
}
