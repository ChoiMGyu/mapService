package com.pathfind.system.repository;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class TransportationSpeedInfoRepositoryImpl implements TransportationSpeedInfoRepository{

    private static final Logger logger = LoggerFactory.getLogger(SidewalkEdgeRepositoryImpl.class);

    private final EntityManager em;

    @Override
    public List<Integer> findSpeedByName(String name) {
        return em.createQuery("select tsi.speed from TransportationSpeedInfo tsi" +
                " where tsi.name = :name", Integer.class)
                .setParameter("name", name)
                .getResultList();
    }
}
