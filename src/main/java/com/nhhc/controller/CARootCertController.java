package com.nhhc.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/CARootCert")
public class CARootCertController {

    @GetMapping("/getCARootCert")
    public String getCARootCert() {
        return "This is a test1";
    }
}
