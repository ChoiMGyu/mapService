package com.pathfind.system.repository;

import com.pathfind.system.domain.SidewalkVertex;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class SidewalkVertexRepositoryImpl implements SidewalkVertexRepository {

    private static final Logger logger = LoggerFactory.getLogger(SidewalkEdgeRepositoryImpl.class);

    private final EntityManager em;
    @Override
    public List<SidewalkVertex> findAll() {
        //logger.info("모든 도보 정점을 반환");
        return em.createQuery("select sv from SidewalkVertex sv" +
                        " left join fetch sv.object o" +
                        " left join fetch o.roadVertex", SidewalkVertex.class)
                .getResultList();
    }
}
