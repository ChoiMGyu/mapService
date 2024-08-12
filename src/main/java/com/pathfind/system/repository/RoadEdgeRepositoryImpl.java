package com.pathfind.system.repository;

import com.pathfind.system.domain.RoadEdge;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class RoadEdgeRepositoryImpl implements RoadEdgeRepository {

    private static final Logger logger = LoggerFactory.getLogger(RoadEdgeRepositoryImpl.class);

    private final EntityManager em;

    @Override
    public List<RoadEdge> findAll() {
        //logger.info("모든 도로 간선을 반환");
        return em.createQuery("select re from RoadEdge re", RoadEdge.class)
                .getResultList();
    }
}
