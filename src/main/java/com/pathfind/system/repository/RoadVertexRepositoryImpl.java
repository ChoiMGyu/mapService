package com.pathfind.system.repository;

import com.pathfind.system.domain.RoadVertex;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class RoadVertexRepositoryImpl implements RoadVertexRepository {

    private static final Logger logger = LoggerFactory.getLogger(RoadVertexRepositoryImpl.class);

    private final EntityManager em;

    @Override
    public List<RoadVertex> findAll() {
        //logger.info("모든 도로 정점을 반환");
        return em.createQuery("select rv from RoadVertex rv" +
                        " left join fetch rv.object o" +
                        " left join fetch o.sidewalkVertex", RoadVertex.class)
                .getResultList();
    }
}
