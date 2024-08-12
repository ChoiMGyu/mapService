/*
 * 클래스 기능 : SseEmitter 리포지토리 구현체
 * 최근 수정 일자 : 2024.05.28(화)
 */
package com.pathfind.system.repository;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Repository
@RequiredArgsConstructor
public class SseEmitterRepositoryImpl implements SseEmitterRepository {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final Map<String, SseEmitter> emitters = new ConcurrentHashMap<>();

    private void setSseEmitterDefaultSetting(String sseEmitterId, SseEmitter sseEmitter) {
        sseEmitter.onTimeout(() -> { // sseEmitter의 제한 시간이 지나면 실행된다.
            logger.info("SseEmitter timed out. id: {}", sseEmitterId);
            sseEmitter.complete();
        });
        sseEmitter.onError(e -> { // sseEmitter에서 error가 발생하면 실행된다.
            logger.warn("SseEmitter error occurred. id: {}, message: {}", sseEmitterId, e.getMessage());
            sseEmitter.complete();
        });
        sseEmitter.onCompletion(() -> { // sseEmitter에서 complete가 되면 실행된다.
            if (emitters.remove(sseEmitterId) != null) {
                logger.info("SseEmitter removed from the storage. id: {}", sseEmitterId);
                logger.info("After remove::SseEmitter storage size: {}", emitters.size());
            }
            logger.info("SseEmitter disconnect successfully. id: {}", sseEmitterId);
        });
    }

    @Override
    public SseEmitter saveSseEmitter(String sseEmitterId, SseEmitter sseEmitter) {
        logger.info("Save sseEmitter...");
        setSseEmitterDefaultSetting(sseEmitterId, sseEmitter);
        emitters.put(sseEmitterId, sseEmitter);
        logger.info("After put::SseEmitter storage size: {}", emitters.size());
        return sseEmitter;
    }

    @Override
    public boolean checkEmitterById(String sseEmitterId) {
        logger.info("check SseEmitter by sseEmitterId");
        try {
            SseEmitter sseEmitter = emitters.get(sseEmitterId);
            return sseEmitter != null;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public SseEmitter findEmitterById(String sseEmitterId) {
        logger.info("Get SseEmitter by sseEmitterId");
        try {
            return emitters.get(sseEmitterId);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public List<Map.Entry<String, SseEmitter>> findAllEmitterByUserId(String userId) {
        logger.info("Get all SseEmitter by userId");
        List<Map.Entry<String, SseEmitter>> sseEmitters = new ArrayList<>();
        for (Map.Entry<String, SseEmitter> entry : emitters.entrySet()) {
            if (entry.getKey().contains(userId)) sseEmitters.add(entry);
        }
        return sseEmitters;
    }

    @Override
    public void deleteEmitterById(String sseEmitterId) {
        logger.info("Delete sseEmitter by sseEmitterId");
        emitters.remove(sseEmitterId);
    }
}
