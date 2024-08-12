/*
 * 클래스 기능 : 검색 기능 구현 클래스
 * 최근 수정 일자 : 2024.06.03(월)
 */
package com.pathfind.system.service;

import com.pathfind.system.domain.ObjType;
import com.pathfind.system.domain.ObjectAddress;
import com.pathfind.system.domain.Objects;
import com.pathfind.system.findPathDto.SearchObjectsPageCSResponse;
import com.pathfind.system.findPathDto.SearchPlaceVCResponse;
import com.pathfind.system.repository.ObjectsPageRepository;
import com.pathfind.system.repository.ObjectsRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ObjectsServiceImpl implements ObjectsService {

    private static final Logger logger = LoggerFactory.getLogger(ObjectsServiceImpl.class);

    private final ObjectsPageRepository objectPageRepository;
    private final ObjectsRepository objectsRepository;
    private final RedisUtil redisUtil;

    public Long search(String searchContent) {
        logger.info("Object의 이름 또는 주소로 검색하였을 때 검색 결과 Object의 id를 반환하는 서비스이다.");

        //이름으로 검색하기
        List<Objects> byName = objectsRepository.findByName(searchContent);


        //주소로 검색하기
        List<Objects> byAddress = objectsRepository.findByAddress(searchContent);

        //만약에 Repository에서 반환된 List의 결과가 Null일 경우 특수한 값을 반환 해야함
        //logger.info("byName : {}, byAddress : {} ", byName.get(0).getId(), byAddress.get(0).getId());
        if (!byName.isEmpty()) {
            //logger.info("이름으로 검색했을 때 결과를 반환하였습니다");
            return byName.get(0).getId();
        } else if (!byAddress.isEmpty()) {
            //logger.info("주소로 검색했을 때 결과를 반환하였습니다");
            return byAddress.get(0).getId();
        } else {
            //logger.info("검색 결과가 없습니다");
            return -1L;
        }
    }

    @Override
    public List<String> findObjectsNameListBySearchWord(String searchWord) {
        searchWord = searchWord.toUpperCase();
        logger.info("Find objects name list by search word. search word: {}", searchWord);
        if (redisUtil.getDataSortedSet(RedisValue.OBJECTS_NAME_SET, RedisValue.GET_ALL_DATA).isEmpty()) {
            redisUtil.setDataSortedSet(RedisValue.OBJECTS_NAME_SET, objectsRepository.findAllObjectsName());
        }
        List<String> result = new ArrayList<>(redisUtil.getDataSortedSet(RedisValue.OBJECTS_NAME_SET, searchWord));
        String finalSearchWord = searchWord;

        Comparator<String> comparingIndexOf = Comparator.comparingInt(a -> a.indexOf(finalSearchWord));
        result.sort(comparingIndexOf.thenComparing(Comparator.naturalOrder()));

        List<String> response = new ArrayList<>();
        for (int i = 0; i < Math.min(10, result.size()); i++) {
            response.add(result.get(i));
        }
        return response;
    }

    public Page<SearchPlaceVCResponse> paging(String searchWord, SearchObjectsPageCSResponse searchObjectsPageCSResponse) {
        searchWord = searchWord.toUpperCase();
        // logger.info("Find objects name list by search word. search word: {}", searchWord);
        if (redisUtil.getDataSortedSet(RedisValue.OBJECTS_NAME_SET, RedisValue.GET_ALL_DATA).isEmpty()) {
            redisUtil.setDataSortedSet(RedisValue.OBJECTS_NAME_SET, objectsRepository.findAllObjectsName());
        }
        List<String> result = new ArrayList<>(redisUtil.getDataSortedSet(RedisValue.OBJECTS_NAME_SET, searchWord));
        String finalSearchWord = searchWord;

        Comparator<String> comparingIndexOf = Comparator.comparingInt(a -> a.indexOf(finalSearchWord));
        result.sort(comparingIndexOf.thenComparing(Comparator.naturalOrder()));

        List<SearchPlaceVCResponse> pageObjects = new LinkedList<>();
        for (int i = 0; i < result.size(); i++) {
//            logger.info("result의 이름: " + result.get(i));
//            logger.info("findByCorrectName 접근 전");
//            logger.info("================================");
            List<Objects> object = objectsRepository.findByCorrectName(result.get(i));
            if (object.isEmpty()) {
                logger.info("에러발생!");
            }
//            logger.info("================================");
//            logger.info("findByCorrectName 접근 후");
//            logger.info("레퍼지토리 접근 후 서비스 계층에서 RoadVertex 접근 전");
//            logger.info("================================");
            String name = object.get(0).getName();
            String description = object.get(0).getDescription();
            ObjectAddress objectAddress = object.get(0).getObjectAddress();
            ObjType objType = object.get(0).getObjectType();
            double longitude = object.get(0).getRoadVertex().getLongitude();
            double latitude = object.get(0).getRoadVertex().getLatitude();
            Long roadVertexId = object.get(0).getRoadVertex().getId() - 1;
            Long sidewalkVertexId = object.get(0).getSidewalkVertex().getId() - 1;

//            logger.info("================================");
//            logger.info("레퍼지토리 접근 후 서비스 계층에서 RoadVertex 접근 후");
//            logger.info("service 계층에서 호출된 object name : " + object.get(0).getName());
//            logger.info("service 계층에서 호출된 object latitude : " + object.get(0).getRoadVertex().getLatitude());
//            logger.info("service 계층에서 호출된 object longitude : " + object.get(0).getRoadVertex().getLongitude());
            SearchPlaceVCResponse temp = new SearchPlaceVCResponse(name, description, objectAddress == null ? null : objectAddress.getAddress(), objType, latitude, longitude, roadVertexId, sidewalkVertexId);
            pageObjects.add(temp);
        }
        Pageable pageable = PageRequest.of(searchObjectsPageCSResponse.getPage(), searchObjectsPageCSResponse.getSize());

        int start = (int) pageable.getOffset();
        int end = Math.min((start + pageable.getPageSize()), pageObjects.size());
        Page<SearchPlaceVCResponse> objectPage = new PageImpl<>(pageObjects.subList(start, end), pageable, pageObjects.size());

        return objectPage;
    }
}
