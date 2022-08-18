package com.example.obspringsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(){
        return "Hello! ";
    }

    @GetMapping("/html")
    public String helloHTML(){
        return "holis";
    }
}
