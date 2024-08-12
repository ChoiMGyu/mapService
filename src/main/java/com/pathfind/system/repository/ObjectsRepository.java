/*
 * 클래스 기능 : 오브젝트 리포지토리 인터페이스
 * 최근 수정 일자 : 2024.05.31(금)
 */
package com.pathfind.system.repository;

import com.pathfind.system.domain.Objects;

import java.util.List;

public interface ObjectsRepository {
    public Objects findById(Long id);

    public List<Objects> findByName(String name);

    public List<Objects> findByAddress(String address);

    public List<String> findAllObjectsName();

    public List<Objects> findByCorrectName(String name);
}
