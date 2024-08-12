package com.pathfind.system.repository;

import com.pathfind.system.domain.SidewalkVertex;
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
class SidewalkVertexRepositoryTest {

    @Autowired SidewalkVertexRepository sidewalkVertexRepository;
    @Autowired EntityManager em;

    @Test
    public void 모든_도보_정점_찾기() throws Exception {
        //given

        //when
        List<SidewalkVertex> vertices = sidewalkVertexRepository.findAll();

        //then
        Assert.assertEquals(vertices.size(), 10);
    }
}