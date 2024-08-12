package com.pathfind.system.repository;

import com.pathfind.system.domain.RoadEdge;

import java.util.List;

public interface RoadEdgeRepository {
    public List<RoadEdge> findAll();
}
