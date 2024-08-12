package com.pathfind.system.repository;

import java.util.List;

public interface TransportationSpeedInfoRepository {
    public List<Integer> findSpeedByName(String name);
}
