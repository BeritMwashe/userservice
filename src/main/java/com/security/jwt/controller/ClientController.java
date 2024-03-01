package com.security.jwt.controller;

import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
@RestController
public class ClientController {
    @GetMapping("/message")
    public String message(){
        var restTemplate=new RestTemplate();
       ResponseEntity<String> response=restTemplate.exchange("http://localhost:8181/hello", HttpMethod.GET,null,String.class);
        return "Success....:: " + response.getBody();
    }

}
