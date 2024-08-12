/*
 * 클래스 기능 : Spring data jpa를 이용한 오브젝트 리포지토리 인터페이스
 * 최근 수정 일자 : 2024.05.31(금)
 */
package com.pathfind.system.repository;

import com.pathfind.system.domain.Objects;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ObjectsPageRepository extends JpaRepository<Objects, Long> {
}
