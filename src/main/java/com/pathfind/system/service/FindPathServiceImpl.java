/*
 * 클래스 기능 : 길 찾기 서비스(서비스1) 구현체
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.service;

import com.pathfind.system.algorithm.Dijkstra;
import com.pathfind.system.algorithm.Graph;
import com.pathfind.system.algorithm.Node;
import com.pathfind.system.domain.*;
import com.pathfind.system.findPathDto.FindPathCSResponse;
import com.pathfind.system.findPathDto.VertexInfo;
import com.pathfind.system.repository.RoadEdgeRepository;
import com.pathfind.system.repository.RoadVertexRepository;
import com.pathfind.system.repository.SidewalkEdgeRepository;
import com.pathfind.system.repository.SidewalkVertexRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class FindPathServiceImpl implements FindPathService {

    private static final Logger logger = LoggerFactory.getLogger(FindPathServiceImpl.class);

    private final RoadEdgeRepository roadEdgeRepository;
    private final RoadVertexRepository roadVertexRepository;
    private final SidewalkEdgeRepository sidewalkEdgeRepository;
    private final SidewalkVertexRepository sidewalkVertexRepository;

    @Override
    public FindPathCSResponse findRoadRoute(Long start, Long end) {
        List<RoadVertex> vertices = roadVertexRepository.findAll();
        int numVertices = vertices.size();
        logger.info("roadVertices size: {}", numVertices);
        Graph graph = new Graph(numVertices);

        List<RoadEdge> edges = roadEdgeRepository.findAll();
        logger.info("roadEdges size: {}", edges.size());
        for (RoadEdge edge : edges) {
            //logger.info("edge 정보 : " + edge.getRoadVertex1() + " " + edge.getRoadVertex2() + " " + edge.getLength());
            Objects object = vertices.get(Math.toIntExact(edge.getRoadVertex2() - 1)).getObject();
            boolean isInfoVertex = object != null && (object.getObjectType() == ObjType.BUILDING || object.getObjectType() == ObjType.LANDMARK);
            graph.addEdge(edge.getRoadVertex1() - 1, edge.getRoadVertex2() - 1, edge.getLength(), isInfoVertex);
        }
        List<Node> nodes = new ArrayList<>();
        for (RoadVertex roadVertex : vertices) {
            Objects object = roadVertex.getObject();
            boolean isInfoVertex = object != null && (object.getObjectType() == ObjType.BUILDING || object.getObjectType() == ObjType.LANDMARK);
            nodes.add(new Node(roadVertex.getId() - 1, 0, isInfoVertex));
        }
        logger.info("findPathInfo(출발점과 도착점 사이 경로의 거리, 거쳐가야 하는 경로의 id) {} to {}", start.intValue(), end.intValue());
        Dijkstra getRoute = new Dijkstra();
        getRoute.dijkstra(nodes, graph, start, end);
        List<Integer> shortestRoute = getRoute.getShortestRoute(start, end);
        List<VertexInfo> routeInfo = new ArrayList<>();
        for (Integer idx : shortestRoute) {
            routeInfo.add(new VertexInfo(vertices.get(idx).getLatitude(), vertices.get(idx).getLongitude()));
        }

        return new FindPathCSResponse(getRoute.getNodes().get(end.intValue()).getDistance(), routeInfo);
    }

    @Override
    public FindPathCSResponse findSidewalkRoute(Long start, Long end) {
        List<SidewalkVertex> vertices = sidewalkVertexRepository.findAll();
        int numVertices = vertices.size();
        logger.info("sidewalkVertices size: {}", numVertices);
        Graph graph = new Graph(numVertices);

        List<SidewalkEdge> edges = sidewalkEdgeRepository.findAll();
        logger.info("sidewalkEdges size: {}", edges.size());
        for (SidewalkEdge edge : edges) {
            //logger.info("edge 정보 : " + edge.getSidewalkVertex1() + " " + edge.getSidewalkVertex2() + " " + edge.getLength());
            Objects object = vertices.get(Math.toIntExact((edge.getSidewalkVertex2() - 1))).getObject();
            boolean isInfoVertex = object != null && (object.getObjectType() == ObjType.BUILDING || object.getObjectType() == ObjType.LANDMARK);
            graph.addEdge(edge.getSidewalkVertex1() - 1, edge.getSidewalkVertex2() - 1, edge.getLength(), isInfoVertex);
        }
        List<Node> nodes = new ArrayList<>();
        for (SidewalkVertex sidewalkVertex : vertices) {
            Objects object = sidewalkVertex.getObject();
            boolean isInfoVertex = object != null && (object.getObjectType() == ObjType.BUILDING || object.getObjectType() == ObjType.LANDMARK);
            nodes.add(new Node(sidewalkVertex.getId() - 1, 0, isInfoVertex));
        }
        logger.info("findPathInfo(출발점과 도착점 사이 경로의 거리, 거쳐가야 하는 경로의 id) {} to {}", start.intValue(), end.intValue());
        Dijkstra getRoute = new Dijkstra();
        getRoute.dijkstra(nodes, graph, start, end);
        List<Integer> shortestRoute = getRoute.getShortestRoute(start, end);
        List<VertexInfo> routeInfo = new ArrayList<>();
        for (Integer idx : shortestRoute) {
            routeInfo.add(new VertexInfo(vertices.get(idx).getLatitude(), vertices.get(idx).getLongitude()));
        }

        return new FindPathCSResponse(getRoute.getNodes().get(end.intValue()).getDistance(), routeInfo);
    }
}
