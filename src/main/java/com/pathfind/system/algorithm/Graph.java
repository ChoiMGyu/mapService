/*
 * 클래스 기능 : 그래프 자료구조를 구현한 클래스
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.algorithm;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
public class Graph {
    private int V;
    @Getter
    private List<List<Node>> adjList;

    public Graph(int V) {
        this.V = V;
        adjList = new ArrayList<>();
        for(int i = 0; i < V; i++) {
            adjList.add(new ArrayList<>());
        }
    }

    public void addEdge(Long u, Long v, double weight, boolean isInfoVertex) {
        adjList.get(u.intValue()).add(new Node(v.intValue(), weight, isInfoVertex));
    }

    public int getNumVertices() {
        return V;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    static class Node {
        int v;
        double weight;
        boolean isInfoVertex;
    }
}
