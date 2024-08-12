/*
 * 클래스 기능 : 길찾기 결과를 JSON 형식으로 반환하는 RESTFUL API를 구현한 클래스
 * 최근 수정 일자 : 2024.02.09(금)
 */
package com.pathfind.system.controller;

import com.pathfind.system.findPathDto.GraphVCRequest;
import com.pathfind.system.findPathDto.FindPathCSResponse;
import com.pathfind.system.findPathDto.ShortestPathVCResponse;
import com.pathfind.system.repository.TransportationSpeedInfoRepository;
import com.pathfind.system.service.FindPathService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class DijkstraController {

    private static final Logger logger = LoggerFactory.getLogger(MemberController.class);

    private final FindPathService findPathService;
    private final TransportationSpeedInfoRepository transportationSpeedInfoRepository;

    @GetMapping("/path")
    public ShortestPathVCResponse shortestPath(@ModelAttribute(value = "graphRequest") @Valid GraphVCRequest request) {
        /*
        //BindingResult를 쓸 수 없으므로 주석 처리를 해놓음. 혹시나 나중에 사용될 수 있으므로 남겨놓음.
        if(request.getStart()==null) {
            result.reject("start", "Empty.start");
        }
        if(result.hasFieldErrors("start") && request.getEnd()==null) {
            result.reject("end", "Empty.end");
        }
        if(result.hasFieldErrors("start") && result.hasFieldErrors("end") && request.getTransportation().isEmpty()) {
            result.reject("transportation", "Empty.transportation");
        }
        if(result.hasErrors()) {
            throw new MethodArgumentNotValidException(null, result);
            return null;
        }*/
        int speed = transportationSpeedInfoRepository.findSpeedByName(request.getTransportation()).get(0);
        logger.info("{} 이동 수단의 속도: {}",request.getTransportation(), speed);

        FindPathCSResponse findPathCSResponse;
        if(request.getTransportation().equals("자동차")) {
            logger.info("도로 길찾기");
            findPathCSResponse = findPathService.findRoadRoute(request.getStart(), request.getEnd());
        }
        else {
            logger.info("도보 길찾기");
            findPathCSResponse = findPathService.findSidewalkRoute(request.getStart(), request.getEnd());
        }

        return new ShortestPathVCResponse(findPathCSResponse.getDistance(), speed, findPathCSResponse.getPath());
    }
}
