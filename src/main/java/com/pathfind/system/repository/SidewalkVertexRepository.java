package com.pathfind.system.repository;

import com.pathfind.system.domain.SidewalkVertex;

import java.util.List;

public interface SidewalkVertexRepository {
    public List<SidewalkVertex> findAll();
}
