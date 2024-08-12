package com.pathfind.system.service;

import com.pathfind.system.domain.RoadVertex;
import com.pathfind.system.domain.SidewalkVertex;
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
class FindPathServiceTest {

    @Autowired
    FindPathService findPathService;

/*    @Test
    public void 도보_길찾기() throws Exception {
        //given
        Long start = 1L, end = 5L;
        long t1, t2, elapsed_time_ms;

        //when
        t1 = System.currentTimeMillis();
        List<SidewalkVertex> sidewalkPath = findPathService.findSidewalkPath(start, end);
        t2 = System.currentTimeMillis();

        //then
        elapsed_time_ms = t2 - t1;
        System.out.println("==================================================");
        System.out.println("elapsed_time_ms after findSidewalkPath() = " + elapsed_time_ms);
        System.out.println("==================================================");
        for (SidewalkVertex sidewalkVertex : sidewalkPath) {
            System.out.println("sidewalkVertex.getId() = " + sidewalkVertex.getId()+", sidewalkVertex.getLatitude() = "+sidewalkVertex.getLatitude()+", sidewalkVertex.getLongitude() = "+sidewalkVertex.getLatitude());
        }
        System.out.println("==================================================");
    }

    @Test
    public void 도로_길찾기() throws Exception {
        //given
        Long start = 1L, end = 5L;
        long t1, t2, elapsed_time_ms;

        //when
        t1 = System.currentTimeMillis();
        List<RoadVertex> roadPath = findPathService.findRoadPath(start, end);
        t2 = System.currentTimeMillis();

        //then
        elapsed_time_ms = t2 - t1;
        System.out.println("==================================================");
        System.out.println("elapsed_time_ms after findRoadPath() = " + elapsed_time_ms);
        System.out.println("==================================================");
        for (RoadVertex roadVertex : roadPath) {
            System.out.println("roadVertex.getId() = " + roadVertex.getId()+", roadVertex.getLatitude() = "+roadVertex.getLatitude()+", roadVertex.getLongitude() = "+roadVertex.getLongitude());
        }
        System.out.println("==================================================");
    }*/
}