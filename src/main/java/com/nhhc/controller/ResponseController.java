package com.nhhc.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class ResponseController {

    @GetMapping("/jetty")
    public String response() {
        return "This is a testing server on Tencent Kona SM Suite";
    }


}
