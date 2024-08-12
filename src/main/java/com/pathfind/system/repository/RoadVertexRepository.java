package com.pathfind.system.repository;

import com.pathfind.system.domain.RoadVertex;

import java.util.List;

public interface RoadVertexRepository {
    public List<RoadVertex> findAll();
}
