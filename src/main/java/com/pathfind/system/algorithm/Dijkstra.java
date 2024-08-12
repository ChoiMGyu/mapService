/*
 * 클래스 기능 : 다익스트라 알고리즘을 구현한 클래스
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.algorithm;

import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

@Getter
public class Dijkstra {
    private static final Logger logger = LoggerFactory.getLogger(Dijkstra.class);

    List<Node> nodes = new ArrayList<>();

    List<Integer> path = new ArrayList<>();

    public void dijkstra(List<Node> n, Graph graph, Long startId, Long endId) {
        PriorityQueue<Node> pq = new PriorityQueue<>(Comparator.comparing(Node::getDistance));
        for (long i = 0L; i < graph.getNumVertices(); i++) {
            Node node = new Node(i, Double.MAX_VALUE, n.get(Math.toIntExact(i)).isInfoVertex());
            if (i == startId) {
                node.setDistance(0);
                pq.add(node);
            }
            nodes.add(node);
            //pq.add(node);
            path.add(0);
        }

        while (!pq.isEmpty()) {
            Node u = pq.poll();
            for (Graph.Node v : graph.getAdjList().get(u.getId().intValue())) {
                if (v.isInfoVertex() && v.getV() != endId) continue;
                double alt = u.getDistance() + ((u.getId().equals(startId) && u.isInfoVertex()) || (v.getV() == endId && v.isInfoVertex()) ? 0 : v.getWeight());
                //double alt = u.getDistance() + v.getWeight();
                //logger.info("u.getDistance : " + u.getDistance() + ", v.getWeight : " + v.getWeight());
                if (alt < nodes.get(v.getV()).getDistance()) {
                    //logger.info("edge relaxation -> alt(u.getDistance() + v.getWeight()) : " + alt + " < nodes.get(v.getV()).getDistance() : " + nodes.get(v.getV()).getDistance());
                    nodes.get(v.getV()).setDistance(alt);
                    //pq.remove(nodes.get(v.getV()));
                    pq.offer(nodes.get(v.getV()));
                    path.set(v.getV(), u.getId().intValue());
                }
            }
        }
    }

    public List<Integer> getShortestRoute(Long startId, Long endId) {
        List<Integer> result = new ArrayList<>();
        Stack<Integer> stack = new Stack<>();
        int endToStart = endId.intValue();
        stack.push(endToStart);

        for(int i = 0; i < path.size(); i++) {
            if(endToStart == startId.intValue()) break;
            endToStart = path.get(endToStart);
            stack.push(endToStart);
        }
        //logger.info("find path start({}) to end({})", startId, endId);
        while (!stack.isEmpty()) {
            //logger.info("path: {}", stack.peek());
            result.add(stack.pop());
        }

        return result;
    }
}
