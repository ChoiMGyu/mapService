package com.pathfind.system.repository;

import com.pathfind.system.domain.SidewalkEdge;

import java.util.List;

public interface SidewalkEdgeRepository {
    public List<SidewalkEdge> findAll();
}
