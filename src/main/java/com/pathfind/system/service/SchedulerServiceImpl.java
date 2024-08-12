/*
 * 클래스 기능 : 휴먼 계정 여부 체크 스케줄러
 * 최근 수정 일자 : 2024.05.24(금)
 */

package com.pathfind.system.service;

import com.pathfind.system.domain.Member;
import com.pathfind.system.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SchedulerServiceImpl implements SchedulerService {

    private static final Logger logger = LoggerFactory.getLogger(SchedulerServiceImpl.class);

    private final MemberRepository memberRepository;

    @Scheduled(cron = "0 0 3 * * ?") //매일 새벽 3시에 checkDormant() 메서드가 실행됨
    @Transactional
    public void checkDormant() {
        logger.info("휴먼 계정 체크가 수행되었습니다.");

        LocalDateTime inActive = LocalDateTime.now().minusMonths(6); //6개월동안 접속 기록이 없다면
        List<Member> members = memberRepository.findAllDormant(inActive);

        for(Member member : members) {
            member.getCheck().changeDormant(true);
        }
    }
}
