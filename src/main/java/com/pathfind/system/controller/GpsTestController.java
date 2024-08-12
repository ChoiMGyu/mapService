package com.pathfind.system.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class GpsTestController {

    @GetMapping("/realtime-yufindpath")
    public String getGeo() {
        return "geo";
    }
}
