package com.pathfind.system.repository;

import com.pathfind.system.domain.RoadVertex;
import jakarta.persistence.EntityManager;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@RunWith(SpringRunner.class)
@SpringBootTest
@Transactional
class RoadVertexRepositoryTest {

    @Autowired RoadVertexRepository roadVertexRepository;
    @Autowired EntityManager em;

    @Test
    public void 모든_도로_정점_찾기() throws Exception {
        //given

        //when
        List<RoadVertex> vertices = roadVertexRepository.findAll();

        //then
        Assert.assertEquals(vertices.size(), 10);
    }
}